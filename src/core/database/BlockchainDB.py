import logging
import os

logger = logging.getLogger(__name__)

from sqlitedict import SqliteDict

from src.core.database.BaseDB import BaseDB
from src.utils.crypto.serialization import bits_to_target


class BlockchainDB(BaseDB):
    def __init__(self):
        self.basepath = "data"
        self.blocks_db_file = os.path.join(self.basepath, "blockchain.sqlite")
        self.index_db_file = os.path.join(self.basepath, "block_index.sqlite")
        self.db = SqliteDict(self.blocks_db_file, autocommit=False)
        self.index_db = SqliteDict(self.index_db_file, autocommit=True)
        self.MAIN_TIP_KEY = "_MAIN_CHAIN_TIP"

    def read(self):
        blocks = []
        current_hash = self.get_main_chain_tip_hash()

        while current_hash:
            block = self.get_block(current_hash)
            if not block:
                break
            blocks.append(block)
            current_hash = block["BlockHeader"]["prevBlockHash"]

            if current_hash == "00" * 32:
                break

        return list(reversed(blocks))

    def write(self, items):
        try:
            for block_dict in items:
                block_hash = block_dict["BlockHeader"]["blockHash"]
                self.db[block_hash] = block_dict
                self.write_index(block_hash, block_dict)

            self.db.commit()
        except Exception as e:
            logging.error(f"Error when writing to db: {e}")
            self.db.rollback()

    def write_block(self, block_dict):
        try:
            block_hash = block_dict["BlockHeader"]["blockHash"]
            self.db[block_hash] = block_dict
            self.db.commit()
            self.write_index(block_hash, block_dict)
            return True

        except Exception as e:
            logging.error(f"Error when writing block {block_hash} to db: {e}")
            self.db.rollback()
            return False

    def write_index(self, block_hash, block_dict):
        prev_hash = block_dict["BlockHeader"]["prevBlockHash"]
        prev_index = self.get_index(prev_hash)
        if prev_index:
            total_work = prev_index["total_work"] + self.calculate_work(block_dict)
        else:
            total_work = self.calculate_work(block_dict)

        index_entry = {
            "hash": block_hash,
            "height": block_dict["Height"],
            "prev_hash": prev_hash,
            "total_work": total_work,
            "status": "valid-header",
        }
        self.index_db[block_hash] = index_entry

    def calculate_work(self, block_dict):
        try:
            bits_hex = block_dict["BlockHeader"]["bits"]
            target = bits_to_target(bytes.fromhex(bits_hex))
            return (2**256) // (target + 1)
        except Exception as e:
            logging.error(f"Error calculating work: {e}. Defaulting to 0")
            return 0

    def get_block(self, block_hash):
        return self.db.get(block_hash)

    def get_index(self, block_hash):
        if block_hash == "00" * 32:
            return None
        return self.index_db.get(block_hash)

    def set_main_chain_tip(self, block_hash):
        self.index_db[self.MAIN_TIP_KEY] = block_hash
        logging.debug(f"New main chain tip set to: {block_hash}")

    def get_main_chain_tip_hash(self):
        return self.index_db.get(self.MAIN_TIP_KEY)

    def update(self, data):
        try:
            self.db.clear()
            self.db.commit()
            self.index_db.clear()
            self.index_db[self.MAIN_TIP_KEY] = None
            self.write(data)

            if data:
                last_block_dict = data[-1]
                last_hash = last_block_dict["BlockHeader"]["blockHash"]
                self.set_main_chain_tip(last_hash)
            return True
        except Exception as e:
            logging.error(f"Error when updating db: {e}")
            self.db.rollback()
            return False

    def lastBlock(self):
        tip_hash = self.get_main_chain_tip_hash()
        if not tip_hash:
            return None
        return self.get_block(tip_hash)
