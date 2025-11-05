import hashlib
import time
import uvicorn
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from src.core.database.BlockchainDB import BlockchainDB
from src.utils.crypto.serialization import decode_base58, encode_base58

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# try Redis
MEMPOOL = {}
UTXOS = {}

MAIN_PREFIX = b"\x6c"
KOR = 100000000
BLOCKCHAIN_CACHE = {"blocks": None, "last_update": 0}
CACHE_TIMEOUT = 10

# Store blockchain data in memory for quick access
def get_blockchain_data():
    global BLOCKCHAIN_CACHE
    now = time.time()
    if (
        not BLOCKCHAIN_CACHE["blocks"]
        or (now - BLOCKCHAIN_CACHE["last_update"]) > CACHE_TIMEOUT
    ):
        try:
            blockchain_db = BlockchainDB()
            blocks = blockchain_db.read()
            if blocks:
                BLOCKCHAIN_CACHE["blocks"] = blocks
                BLOCKCHAIN_CACHE["last_update"] = now
        except Exception as e:
            print(f"Error while fetching blockchain data: {e}") 
            return BLOCKCHAIN_CACHE["blocks"] if BLOCKCHAIN_CACHE["blocks"] else []

    return BLOCKCHAIN_CACHE["blocks"]


# encode a public key hash to a Base58Check address
def encode_base58_checksum(h160_bytes):
    payload = MAIN_PREFIX + h160_bytes
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    full_payload = payload + checksum
    return encode_base58(full_payload)


# Find a transaction in a list of blocks by its ID
def find_transaction_in_blocks(tx_id, blocks):
    if not blocks:
        return None
    for block in blocks:
        for tx in block.get("Txs", []):
            if tx.get("TxId") == tx_id:
                return tx
    return None


# Format transaction details for API response
def format_transaction_details(tx, block, blocks):
    tx_id = tx.get("TxId")
    total_in = 0
    from_addresses = set()

    for inp in tx.get("tx_ins", []):
        if inp.get("prev_tx") == "00" * 32:
            from_addresses.add("Coinbase")
            continue
        prev_tx_data = find_transaction_in_blocks(inp.get("prev_tx"), blocks)

        if prev_tx_data:
            try:
                spent_output = prev_tx_data["tx_outs"][inp.get("prev_index")]
                total_in += spent_output.get("amount", 0)
                h160_bytes = bytes.fromhex(spent_output["script_pubkey"]["cmds"][2])
                from_addresses.add(encode_base58_checksum(h160_bytes))

            except (IndexError, KeyError, ValueError, TypeError):
                from_addresses.add("Error")

    total_out = sum(out.get("amount", 0) for out in tx.get("tx_outs", []))
    to_addresses_details = []
    sent_value = 0

    for out in tx.get("tx_outs", []):
        try:
            h160_bytes = bytes.fromhex(out["script_pubkey"]["cmds"][2])
            recipient_address = encode_base58_checksum(h160_bytes)
            amount = out.get("amount", 0)
            to_addresses_details.append(
                {"address": recipient_address, "amount": amount / KOR}
            )

            if recipient_address not in from_addresses:
                sent_value += amount

        except (IndexError, KeyError, ValueError, TypeError):
            to_addresses_details.append(
                {"address": "Error", "amount": out.get("amount", 0) / KOR}
            )

    if "Coinbase" in from_addresses:
        fee = 0
        value = total_out
    else:
        fee = total_in - total_out
        value = sent_value if sent_value > 0 else total_out

    return {
        "hash": tx_id,
        "block_height": block.get("Height"),
        "block_hash": block.get("BlockHeader", {}).get("blockHash"),
        "from": list(from_addresses),
        "to": [item["address"] for item in to_addresses_details],
        "value": value / KOR,
        "fee": fee / KOR,
        "status": "success",
    }


# Extract miner address from coinbase transaction of a block
def get_miner_address(block):
    if not block or not block.get("Txs"):
        return "N/A"

    coinbase_tx = block["Txs"][0]
    if coinbase_tx.get("tx_ins", [{}])[0].get("prev_tx") == "00" * 32:
        try:
            h160_hex = coinbase_tx["tx_outs"][0]["script_pubkey"]["cmds"][2]
            h160_bytes = bytes.fromhex(h160_hex)
            return encode_base58_checksum(h160_bytes)

        except (IndexError, KeyError, TypeError, ValueError):
            return "Error Reading Miner Address"

    return "N/A"


# ==============================================================================
# API ENDPOINTS
# ==============================================================================

@app.get("/api/stats")
async def get_stats():
    blocks_db = get_blockchain_data()
    active_addresses = set()
    total_transactions = 0

    if blocks_db:
        for block in blocks_db:
            total_transactions += block.get("TxCount", 0)
            for tx in block.get("Txs", []):
                for tx_out in tx.get("tx_outs", []):
                    try:
                        active_addresses.add(tx_out["script_pubkey"]["cmds"][2])
                    except (IndexError, KeyError, TypeError, ValueError):
                        continue

    return {
        "total_transactions": total_transactions,
        "active_addresses": len(active_addresses),
        "network_hashrate": "N/A",  
    }


@app.get("/api/blocks")
async def get_blocks():
    blocks_db = get_blockchain_data()
    if not blocks_db:
        return []

    formatted_blocks = []
    for block in reversed(blocks_db):
        header = block.get("BlockHeader", {})
        block_size_used = (block.get("Blocksize", 0) / 1000000) * 100

        formatted_blocks.append(
            {
                "height": block.get("Height"),
                "hash": header.get("blockHash"),
                "timestamp": datetime.fromtimestamp(
                    header.get("timestamp", 0), timezone.utc
                ).isoformat(),
                "transaction_count": block.get("TxCount"),
                "miner": get_miner_address(block),
                "size_used": block_size_used,
                "reward": 50, 
            }
        )
    return formatted_blocks


@app.get("/api/block/{block_hash}")
async def get_block_details(block_hash: str):
    blocks_db = get_blockchain_data()
    if not blocks_db:
        raise HTTPException(status_code=404, detail="Blockchain is empty")

    for block in blocks_db:
        header = block.get("BlockHeader", {})
        if header.get("blockHash") == block_hash:
            formatted_txs = []
            if block.get("Txs"):
                for tx in block["Txs"]:
                    inputs = []
                    for inp in tx.get("tx_ins", []):
                        if inp.get("prev_tx") == "00" * 32:
                            inputs.append({"address": "Coinbase"})
                        else:
                            prev_tx_data = find_transaction_in_blocks(
                                inp.get("prev_tx"), blocks_db
                            )
                            sender_address = "Address not found"
                            if prev_tx_data:
                                try:
                                    spent_output = prev_tx_data["tx_outs"][
                                        inp.get("prev_index")
                                    ]
                                    h160_hex = spent_output["script_pubkey"]["cmds"][2]
                                    h160_bytes = bytes.fromhex(h160_hex)
                                    sender_address = encode_base58_checksum(h160_bytes)
                                except (IndexError, KeyError, TypeError, ValueError):
                                    sender_address = "Erreur while reading address"
                            inputs.append({"address": sender_address})

                    outputs = []
                    for out in tx.get("tx_outs", []):
                        if (
                            "script_pubkey" in out
                            and len(out["script_pubkey"].get("cmds", [])) > 2
                        ):
                            try:
                                h160_hex = out["script_pubkey"]["cmds"][2]
                                h160_bytes = bytes.fromhex(h160_hex)
                                address = encode_base58_checksum(h160_bytes)
                                amount = out.get("amount", 0) / 100000000
                                outputs.append({"address": address, "amount": amount})
                            except (IndexError, KeyError, TypeError, ValueError):
                                continue
                    formatted_txs.append(
                        {"hash": tx.get("TxId"), "inputs": inputs, "outputs": outputs}
                    )

            return {
                "block_number": block.get("Height"),
                "hash": header.get("blockHash"),
                "previous_hash": header.get("prevBlockHash"),
                "confirmations": len(blocks_db) - block.get("Height"),
                "transaction_count": block.get("TxCount"),
                "miner": get_miner_address(block),
                "size": block.get("Blocksize"),
                "merkle_root": header.get("merkleRoot"),
                "nonce": header.get("nonce"),
                "timestamp": datetime.fromtimestamp(
                    header.get("timestamp", 0), timezone.utc
                ).isoformat(),
                "transactions": formatted_txs,
                "reward": 50,
                "version": header.get("version"),
                "bits": header.get("bits"),
            }

    raise HTTPException(status_code=404, detail="Bloc not found")


@app.get("/api/transactions")
async def get_transactions():
    blocks_db = get_blockchain_data()
    all_txs = []
    limit = 50

    if not blocks_db:
        return []

    for block in reversed(blocks_db):
        if len(all_txs) >= limit:
            break
        for tx in reversed(block.get("Txs", [])[1:]):
            if len(all_txs) >= limit:
                break
            all_txs.append(format_transaction_details(tx, block, blocks_db))

    return all_txs


@app.get("/api/tx/{tx_hash}")
async def get_transaction_details(tx_hash: str):
    blocks_db = get_blockchain_data()
    if not blocks_db:
        raise HTTPException(status_code=404, detail="Blockchain not found")

    for block in blocks_db:
        for tx in block.get("Txs", []):
            if tx.get("TxId") == tx_hash:
                formatted_tx = format_transaction_details(tx, block, blocks_db)
                formatted_tx["status"] = "Confirmed"
                formatted_tx["timestamp"] = datetime.fromtimestamp(
                    block.get("BlockHeader", {}).get("timestamp", 0), timezone.utc
                ).isoformat()
                formatted_tx["confirmations"] = len(blocks_db) - block.get("Height")

                detailed_inputs = []
                for inp in tx.get("tx_ins", []):
                    if inp.get("prev_tx") == "00" * 32:
                        detailed_inputs.append({"address": "Coinbase", "value": None})
                    else:
                        prev_tx_data = find_transaction_in_blocks(
                            inp.get("prev_tx"), blocks_db
                        )
                        if prev_tx_data:
                            try:
                                spent_output = prev_tx_data["tx_outs"][
                                    inp.get("prev_index")
                                ]
                                h160_bytes = bytes.fromhex(
                                    spent_output["script_pubkey"]["cmds"][2]
                                )
                                address = encode_base58_checksum(h160_bytes)
                                value = spent_output.get("amount", 0) / KOR
                                detailed_inputs.append(
                                    {"address": address, "value": value}
                                )
                            except (IndexError, KeyError, TypeError, ValueError):
                                pass

                detailed_outputs = []
                for out in tx.get("tx_outs", []):
                    try:
                        h160_bytes = bytes.fromhex(out["script_pubkey"]["cmds"][2])
                        address = encode_base58_checksum(h160_bytes)
                        value = out.get("amount", 0) / KOR
                        detailed_outputs.append({"address": address, "value": value})
                    except (IndexError, KeyError, TypeError, ValueError):
                        pass

                formatted_tx["inputs"] = detailed_inputs
                formatted_tx["outputs"] = detailed_outputs

                return formatted_tx

    raise HTTPException(status_code=404, detail="Transaction not found")


@app.get("/api/address/{public_address}")
async def get_address_details(public_address: str):
    try:
        target_h160 = decode_base58(public_address)
    except Exception as e:
        print(f"Error while decoding address{public_address}: {e}") 
        raise HTTPException(status_code=400, detail="Address format invalid")

    blocks_db = get_blockchain_data()
    if not blocks_db:
        return {
            "address": public_address,
            "transactions": [],
            "error": "Blockchain is empty",
        }

    total_received_kores = 0
    total_sent_kores = 0
    address_transactions = []
    processed_tx_ids = set()

    for block in blocks_db:
        for tx in block.get("Txs", []):
            tx_id = tx.get("TxId")
            if tx_id in processed_tx_ids:
                continue

            is_sender = False
            is_receiver = False
            value_in = 0
            value_out = 0
            from_addresses = set()
            to_addresses_details = []

            for tx_in in tx.get("tx_ins", []):
                if tx_in.get("prev_tx") == "00" * 32:
                    from_addresses.add("Coinbase")
                    continue

                prev_tx = find_transaction_in_blocks(tx_in.get("prev_tx"), blocks_db)
                if prev_tx:
                    try:
                        spent_output = prev_tx["tx_outs"][tx_in.get("prev_index")]
                        h160_bytes = bytes.fromhex(
                            spent_output["script_pubkey"]["cmds"][2]
                        )
                        from_addresses.add(encode_base58_checksum(h160_bytes))
                        if h160_bytes == target_h160:
                            is_sender = True
                            value_out += spent_output.get("amount", 0)
                    except (IndexError, KeyError, ValueError, TypeError):
                        continue

            for tx_out in tx.get("tx_outs", []):
                try:
                    h160_bytes = bytes.fromhex(tx_out["script_pubkey"]["cmds"][2])
                    receiver_address = encode_base58_checksum(h160_bytes)
                    amount = tx_out.get("amount", 0)
                    to_addresses_details.append(
                        {"address": receiver_address, "amount": amount / KOR}
                    )
                    if h160_bytes == target_h160:
                        is_receiver = True
                        value_in += amount
                except (ValueError, TypeError, IndexError):
                    continue

            if is_sender or is_receiver:
                net_effect = value_in - value_out
                direction = "IN" if is_receiver else "OUT"
                if is_sender and is_receiver:
                    if net_effect < 0:
                        direction = "OUT"
                    else:
                        direction = "IN"

                if is_sender:
                    total_sent_kores += value_out
                if is_receiver:
                    total_received_kores += value_in

                address_transactions.append(
                    {
                        "hash": tx_id,
                        "block_height": block.get("Height"),
                        "block_hash": block.get("BlockHeader", {}).get("blockHash"),
                        "timestamp": datetime.fromtimestamp(
                            block.get("BlockHeader", {}).get("timestamp", 0),
                            timezone.utc,
                        ).isoformat(),
                        "from": list(from_addresses),
                        "to": to_addresses_details,
                        "direction": direction,
                        "value": abs(net_effect) / KOR,
                    }
                )
                processed_tx_ids.add(tx_id)

    current_balance_kores = total_received_kores - total_sent_kores

    return {
        "address": public_address,
        "total_received": total_received_kores / KOR,
        "total_sent": total_sent_kores / KOR,
        "current_balance": current_balance_kores / KOR,
        "transaction_count": len(address_transactions),
        "transactions": sorted(
            address_transactions, key=lambda x: x["block_height"], reverse=True
        ),
    }


@app.get("/api/mempool")
async def get_mempool():
    formatted_txs = []
    current_mempool = dict(MEMPOOL)
    for tx_id, tx_obj in current_mempool.items():
        try:
            total_value = sum(out.amount for out in tx_obj.tx_outs)
            formatted_txs.append(
                {
                    "hash": tx_id,
                    "value": total_value / KOR,
                    "received_time": getattr(tx_obj, "received_time", time.time()),
                }
            )
        except Exception as e:
            print(f"Error while formating tx {tx_id} in mempool: {e}")
            continue
    return formatted_txs


@app.get("/api/search/{query}")
async def search_blockchain(query: str):
    blocks_db = get_blockchain_data()
    if not blocks_db:
        return {"found": False}

    try:
        decode_base58(query)
        return {"found": True, "type": "address", "identifier": query}
    except Exception:
        pass

    if query.isdigit():
        for block in blocks_db:
            if block.get("Height") == int(query):
                return {
                    "found": True,
                    "type": "block",
                    "identifier": block["BlockHeader"]["blockHash"],
                }

    if len(query) == 64:
        for block in blocks_db:
            if block["BlockHeader"]["blockHash"] == query:
                return {"found": True, "type": "block", "identifier": query}
            for tx in block.get("Txs", []):
                if tx.get("TxId") == query:
                    return {
                        "found": True,
                        "type": "transaction",
                        "identifier": query
                    }

    return {"found": False}

def main(utxos, MemPool, port, host="0.0.0.0"):
    global UTXOS, MEMPOOL
    UTXOS = utxos
    MEMPOOL = MemPool
    get_blockchain_data() 
    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config)
    server.run()