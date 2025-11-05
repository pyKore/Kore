import logging
import os
import sys
import time
from queue import Queue
from threading import Event, Thread

sys.path.append(os.getcwd())

from src.net.services.api_service import main as web_main
from src.core.chain.managers.ChainManager import ChainManager
from src.core.chain.managers.UTXOManager import UTXOManager
from src.core.database.TxIndexDB import TxIndexDB
from src.core.database.UTXODB import UTXODB
from src.core.database.BlockchainDB import BlockchainDB
from src.core.database.MempoolDB import MempoolDB
from src.core.genesis import create_genesis_block
from src.net.services.rpc_service import rpcServer
from src.net.sync import SyncManager
from src.utils.config_loader import load_config
from src.utils.logging_config import setup_logging

logger = logging.getLogger(__name__)


def handle_incoming_blocks(incoming_blocks_queue, chain_manager, broadcast_queue):
    logger.debug("Block processing worker started")
    while True:
        try:
            block_obj = incoming_blocks_queue.get()
            if not block_obj:
                continue

            logger.debug(f"Processing block {block_obj.Height} from queue...")

            if chain_manager.process_new_block(block_obj):
                logger.debug(
                    f"Block {block_obj.Height} accepted, adding to broadcast queue"
                )
                broadcast_queue.put(block_obj)
            else:
                logger.warning(f"Block {block_obj.Height} rejected by ChainManager")

        except Exception as e:
            logger.error(f"Error in block processing worker: {e}")


def handle_broadcasts(broadcast_queue, sync_manager, new_block_event):
    while True:
        block_to_broadcast = broadcast_queue.get()
        if block_to_broadcast and sync_manager:
            sync_manager.broadcast_block(block_to_broadcast)
            new_block_event.set()


def handle_new_transactions(new_tx_queue, sync_manager, chain_manager):
    while True:
        try:
            tx = new_tx_queue.get()
            if not tx:
                continue
            was_added = chain_manager.add_transaction_to_mempool(tx)

            if was_added:
                sync_manager.broadcast_tx(tx)

        except Exception as e:
            logger.error(f"Error in thread {e}")


def reload_mempool(mempool_db, chain_manager):
    logger.debug(f"Reloading persistent mempool. Found {len(mempool_db)} transactions.")
    tx_ids_to_remove = []

    for tx_id, tx in mempool_db.items():
        if not chain_manager.validator.validate_transaction(tx, is_in_block=False):
            logger.warning(
                f"Removing invalid transaction {tx_id} from persistent mempool (already mined or double-spend)"
            )
            tx_ids_to_remove.append(tx_id)
        else:
            logger.debug(f"Reloaded valid transaction {tx_id} into mempool")

    for tx_id in tx_ids_to_remove:
        try:
            del mempool_db[tx_id]
        except KeyError:
            logger.warning(f"Transaction {tx_id} was already removed during validation")

    logger.info(f"Mempool reloaded. Kept {len(mempool_db)} valid transactions")


def main():
    setup_logging()
    config = load_config()

    host = config["NETWORK"]["host"]
    p2p_port = int(config["P2P"]["port"])
    api_port = int(config["API"]["port"])
    rpc_port = api_port + 1

    mining_process_manager = {"shutdown_requested": False}
    new_tx_queue = Queue()
    broadcast_queue = Queue()
    incoming_blocks_queue = Queue()
    new_block_event = Event()

    logger.debug("Initializing databases...")
    db = BlockchainDB()
    utxos_db = UTXODB()
    mempool_db = MempoolDB()
    txindex_db = TxIndexDB()

    chain_manager = ChainManager(db, utxos_db, mempool_db, txindex_db, new_block_event)
    utxo_manager = UTXOManager(utxos_db)

    if not db.get_main_chain_tip_hash():
        logger.debug("No main chain tip found. Checking for Genesis block...")
        genesis = create_genesis_block()
        genesis_hash = genesis.BlockHeader.generateBlockHash()

        if not db.get_block(genesis_hash):
            logger.debug(
                "No Genesis block found. Creating and writing Genesis block..."
            )
            genesis.BlockHeader.to_hex()
            tx_json_list = [tx.to_dict() for tx in genesis.Txs]
            block_to_save = {
                "Height": genesis.Height,
                "Blocksize": genesis.Blocksize,
                "BlockHeader": genesis.BlockHeader.__dict__,
                "TxCount": len(tx_json_list),
                "Txs": tx_json_list,
            }
            db.write_block(block_to_save)
        else:
            logger.debug("Genesis block found in DB")

        logger.debug("Connecting Genesis block to UTXO set and TxIndex...")
        chain_manager.connect_block(genesis)
        db.set_main_chain_tip(genesis_hash)
        utxos_db.set_meta("last_block_hash", genesis_hash)
        utxos_db.commit()
        logger.debug("Genesis block processed")

    last_hash_chain = db.get_main_chain_tip_hash()
    last_hash_utxo_db = utxos_db.get_meta("last_block_hash")

    if last_hash_chain == last_hash_utxo_db:
        logger.debug(f"UTXO set is in sync with main chain tip: {last_hash_chain}")
        logger.debug(f"Loaded {len(utxos_db)} UTXOs")
    else:
        logger.info(f"UTXO set is out of sync. Rebuilding... This may take a while...")
        logger.debug("Clearing TxIndex for rebuild...")
        txindex_db.clear()

        logger.debug("Rebuilding UTXO set...")
        utxo_manager.build_utxos_from_db()

        logger.debug("Rebuilding TxIndex...")
        all_blocks = db.read()
        for block_dict in all_blocks:
            block_hash = block_dict["BlockHeader"]["blockHash"]
            for tx in block_dict["Txs"]:
                txindex_db[tx["TxId"]] = block_hash
        logger.debug("TxIndex rebuilt")

        utxos_db.set_meta("last_block_hash", last_hash_chain)
        utxos_db.commit()
        logger.info(f"UTXO set rebuilt. {len(utxos_db)} UTXOs found")

    reload_mempool(mempool_db, chain_manager)

    sync_manager = SyncManager(
        host,
        p2p_port,
        new_block_event,
        mempool_db,
        utxos_db,
        chain_manager,
        incoming_blocks_queue,
    )

    # Thread P2P
    p2p_server_thread = Thread(target=sync_manager.spin_up_the_server)
    p2p_server_thread.daemon = True
    p2p_server_thread.start()

    # API Thread
    api_thread = Thread(
        target=web_main, args=(utxos_db, mempool_db, api_port, host)
    )
    api_thread.daemon = True
    api_thread.start()
    logger.info(f"API server started on http://{host}:{api_port}")

    # RPC Thread
    rpc_thread = Thread(
        target=rpcServer,
        args=(
            host,
            rpc_port,
            utxos_db,
            mempool_db,
            mining_process_manager,
            new_tx_queue,
            broadcast_queue,
            new_block_event,
            chain_manager,
            incoming_blocks_queue,
        ),
    )
    rpc_thread.daemon = True
    rpc_thread.start()

    # Tx Thread
    tx_handler_thread = Thread(
        target=handle_new_transactions, args=(new_tx_queue, sync_manager, chain_manager)
    )
    tx_handler_thread.daemon = True
    tx_handler_thread.start()

    broadcast_handler_thread = Thread(
        target=handle_broadcasts, args=(broadcast_queue, sync_manager, new_block_event)
    )
    broadcast_handler_thread.daemon = True
    broadcast_handler_thread.start()

    block_handler_thread = Thread(
        target=handle_incoming_blocks,
        args=(incoming_blocks_queue, chain_manager, broadcast_queue),
    )
    block_handler_thread.daemon = True
    block_handler_thread.start()

    time.sleep(2)

    config = load_config()
    if "SEED_NODES" in config:
        logger.info("Connecting to seed nodes...")
        for key, address in config["SEED_NODES"].items():
            try:
                peer_host, peer_port_str = address.split(":")
                peer_port = int(peer_port_str)
                sync_manager.connect_to_peer(peer_host, peer_port)
            except Exception as e:
                logger.warning(
                    f"Invalid seed node address format or connection failed: {address} ({e})"
                )

    try:
        while not mining_process_manager.get("shutdown_requested", False):
            time.sleep(2)

    except KeyboardInterrupt:
        logger.info("\nShutting down daemon...")


if __name__ == "__main__":
    main()
