import json
import logging
import socketserver
import time
from io import BytesIO

logger = logging.getLogger(__name__)

from src.core.chain.chainparams import KOR
from src.core.chain.difficulty import calculate_new_bits
from src.core.chain.mempool import Mempool
from src.core.chain.primitives.block import Block
from src.core.database.AccountDB import AccountDB
from src.core.database.BlockchainDB import BlockchainDB
from src.core.txs.coinbase_tx import CoinbaseTx
from src.core.txs.send import Send
from src.utils.crypto.serialization import decode_base58
from src.wallet.wallet import wallet

FEE_RATE_NORMAL = 500
RPC_CONTEXT = {}


def get_block_template(mempool, utxos):
    db = BlockchainDB()
    last_block = db.lastBlock()
    if not last_block:
        raise Exception("Blockchain has not been initialized")

    mempool_manager = Mempool(mempool, utxos)
    block_data = mempool_manager.get_transactions_for_block()

    height = last_block["Height"] + 1
    coinbase_tx = CoinbaseTx(height).CoinbaseTransaction(fees=block_data["fees"])
    if not coinbase_tx:
        raise Exception("Impossible to create coinbase transaction")

    transactions = [coinbase_tx.to_dict()] + [
        tx.to_dict() for tx in block_data["transactions"]
    ]
    bits = calculate_new_bits(height)

    return {
        "version": 1,
        "previous_block_hash": last_block["BlockHeader"]["blockHash"],
        "transactions": transactions,
        "bits": bits.hex(),
        "height": height,
    }


def calculate_wallet_balances(wallets, utxos_db):
    wallet_map = {}
    h160_list = []
    for wallet in wallets:
        wallet["balance"] = 0.0
        try:
            h160_bytes = decode_base58(wallet.get("PublicAddress"))
            h160_hex = h160_bytes.hex()
            wallet_map[h160_hex] = wallet
            h160_list.append(h160_bytes)
        except Exception:
            continue

    if not h160_list:
        return wallets

    balances_kores = utxos_db.get_balances(h160_list)

    for h160_hex, wallet in wallet_map.items():
        balance_kor = balances_kores.get(h160_hex, 0) / 100000000
        wallet["balance"] = balance_kor

    return wallets


class TCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            full_data = b""
            while True:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                full_data += chunk
                try:
                    command = json.loads(full_data.decode("utf-8"))
                    break
                except json.JSONDecodeError:
                    continue

            if not full_data:
                return

            cmd = command.get("command")
            params = command.get("params", {})

            utxos = RPC_CONTEXT.get("utxos")
            mempool = RPC_CONTEXT.get("mempool")
            new_tx_queue = RPC_CONTEXT.get("new_tx_queue")
            broadcast_queue = RPC_CONTEXT.get("broadcast_queue")
            new_block_event = RPC_CONTEXT.get("new_block_event")
            mining_process_manager = RPC_CONTEXT.get("mining_process_manager")
            chain_manager = RPC_CONTEXT.get("chain_manager")
            incoming_blocks_queue = RPC_CONTEXT.get("incoming_blocks_queue")

            response = {}

            if cmd == "ping":
                response = {"status": "success", "message": "pong"}

            elif cmd == "get_work":
                new_block_event.wait(timeout=60.0)
                new_block_event.clear()
                try:
                    template = get_block_template(mempool, utxos)
                    response = {"status": "success", "template": template}
                except Exception as e:
                    response = {"status": "error", "message": str(e)}

            elif cmd == "submit_block":
                block_hex = params.get("block_hex")
                if not block_hex:
                    response = {
                        "status": "error",
                        "message": "block_hex parameter is required",
                    }
                elif not incoming_blocks_queue:
                    response = {
                        "status": "error",
                        "message": "Block processing queue is not available",
                    }
                else:
                    try:
                        block_bytes = bytes.fromhex(block_hex)
                        block = Block.parse(BytesIO(block_bytes))
                        incoming_blocks_queue.put(block)
                        response = {
                            "status": "success",
                            "message": f"Block {block.Height} submitted for processing",
                        }
                    except (ValueError, IndexError, TypeError, SyntaxError) as e:
                        logger.warning(f"Failed to parse submitted block: {e}")
                        response = {
                            "status": "error",
                            "message": f"Invalid block format or hex: {e}",
                        }
                    except Exception as e:
                        logger.error(
                            f"Unexpected error in submit_block: {e}", exc_info=True
                        )
                        response = {
                            "status": "error",
                            "message": f"Error processing block:{e}",
                        }

            elif cmd == "get_chain_height":
                try:
                    db = BlockchainDB()
                    last_block = db.lastBlock()
                    height = last_block["Height"] if last_block else -1
                    response = {"status": "success", "height": height}
                except Exception as e:
                    response = {
                        "status": "error",
                        "message": f"Impossible to get chain height:{e}",
                    }

            elif cmd == "create_wallet":
                wallet_name = params.get("name")
                if not wallet_name:
                    response = {"status": "error", "message": "Wallet name is required"}

                acc = wallet()
                wallet_data = acc.createKeys(wallet_name)
                if AccountDB().save_wallet(wallet_name, wallet_data):
                    response = {
                        "status": "success",
                        "message": f"Wallet '{wallet_name}' created.",
                        "wallet": wallet_data,
                    }
                else:
                    response = {
                        "status": "error",
                        "message": f"Wallet '{wallet_name}' already exists.",
                    }

            elif cmd == "get_wallets":
                try:
                    all_wallets = AccountDB().get_all_wallets()
                    wallets_with_balances = calculate_wallet_balances(
                        all_wallets, utxos
                    )
                    response = {"status": "success", "wallets": wallets_with_balances}
                except Exception as e:
                    response = {
                        "status": "error",
                        "message": f"Could not retrieve wallets:{e}",
                    }

            elif cmd == "send_tx":
                try:
                    if not all(k in params for k in ["from", "to", "amount"]):
                        response = {
                            "status": "error",
                            "message": "Missing required parameters (from, to, amount)",
                        }
                        self.request.sendall(json.dumps(response).encode("utf-8"))

                    from_addr = params["from"]
                    to_addr = params["to"]
                    amount_float = float(params["amount"])
                    fee_rate = int(params.get("fee_rate", FEE_RATE_NORMAL))

                    send_handler = Send(
                        from_addr,
                        to_addr,
                        amount_float,
                        fee_rate,
                        utxos,
                        mempool,
                    )

                    tx = send_handler.prepareTransaction()

                    if not tx:
                        response = {
                            "status": "error",
                            "message": "Failed to create transaction. Check balance, addresses, and UTXO availability",
                        }
                    elif not new_tx_queue:
                        response = {
                            "status": "error",
                            "message": "Cannot broadcast transaction, daemon queue not available",
                        }
                    else:
                        new_tx_queue.put(tx)
                        response = {
                            "status": "success",
                            "message": "Transaction sent to daemon for processing",
                            "txid": tx.id(),
                        }

                except (ValueError, TypeError):
                    response = {
                        "status": "error",
                        "message": "Invalid amount or fee_rate. Must be a number",
                    }
                except KeyError as e:
                    response = {
                        "status": "error",
                        "message": f"Missing parameter: {e}",
                    }
                except Exception as e:
                    logger.error(f"Unexpected error in send_tx: {e}", exc_info=True)
                    response = {
                        "status": "error",
                        "message": f"Internal error sending transaction: {e}",
                    }

            elif cmd == "get_mempool":
                try:
                    formatted_txs = []
                    current_mempool = dict(mempool)
                    for tx_id, tx_obj in current_mempool.items():
                        total_value = sum(out.amount for out in tx_obj.tx_outs)
                        formatted_txs.append(
                            {
                                "hash": tx_id,
                                "value": total_value / KOR,
                                "fee": getattr(tx_obj, "fee", 0),
                                "received_time": getattr(
                                    tx_obj, "receivedTime", time.time()
                                ),
                            }
                        )
                    response = {"status": "success", "mempool": formatted_txs}
                except Exception as e:
                    response = {
                        "status": "error",
                        "message": f"Could not retrieve mempool: {e}",
                    }

            elif cmd == "getinfo":
                try:
                    db = BlockchainDB()
                    last_block = db.lastBlock()
                    height = last_block["Height"] if last_block else -1

                    mempool_size = len(mempool)

                    wallet_count = len(AccountDB().get_all_wallets())

                    response = {
                        "status": "success",
                        "info": {
                            "height": height,
                            "mempool_size": mempool_size,
                            "wallet_count": wallet_count,
                        },
                    }
                except Exception as e:
                    response = {
                        "status": "error",
                        "message": f"Could not retrieve info: {e}",
                    }

            elif cmd == "shutdown":
                if mining_process_manager:
                    mining_process_manager["shutdown_requested"] = True
                response = {"status": "success", "message": "Daemon shutdown initiated"}

            else:
                response = {
                    "status": "error",
                    "message": f"Command '{cmd}' not recognized",
                }

            self.request.sendall(json.dumps(response).encode("utf-8"))
        except Exception as e:
            logger.error(f"Error in RPC request: {e}")


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


def rpcServer(
    host,
    rpcPort,
    utxos,
    mempool,
    mining_process_manager,
    new_tx_queue,
    broadcast_queue,
    new_block_event,
    chain_manager,
    incoming_blocks_queue,
):
    global RPC_CONTEXT
    RPC_CONTEXT = {
        "utxos": utxos,
        "mempool": mempool,
        "mining_process_manager": mining_process_manager,
        "new_tx_queue": new_tx_queue,
        "broadcast_queue": broadcast_queue,
        "new_block_event": new_block_event,
        "chain_manager": chain_manager,
        "incoming_blocks_queue": incoming_blocks_queue,
    }

    server = ThreadedTCPServer((host, rpcPort), TCPRequestHandler)
    logger.debug(f"RPC server started, listening on port {rpcPort}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
