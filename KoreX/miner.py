import json
import socket
import time
from threading import Event, Thread

from KernelX.pow import mine
from src.core.block import Block
from src.core.blockheader import BlockHeader
from src.core.transaction import Tx
from src.utils.serialization import merkle_root


class Miner:
    def __init__(self, rpc_host, rpc_port):
        self.rpc_address = (rpc_host, rpc_port)
        self.stop_mining_event = Event()
        self.mining_thread = None

        self.current_work_prev_hash = None
        self.current_work_merkle_root = None

    def send_rpc_command(self, command, timeout=120.0):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect(self.rpc_address)
                s.sendall(json.dumps(command).encode("utf-8"))

                response_data = b""
                while True:
                    chunk = s.recv(8192)
                    if not chunk:
                        break
                    response_data += chunk

                return json.loads(response_data.decode("utf-8"))
        except socket.timeout:
            return None
        except (socket.error, json.JSONDecodeError, ConnectionResetError) as e:
            print(f"\nRPC call failed: {e}")
            return None

    def mine_block_thread(self, block_header, block_height, transactions):
        mined_header = mine(block_header, self.stop_mining_event)

        if self.stop_mining_event.is_set():
            return

        if not mined_header:
            print("Mining failed")
            return

        print(f"\nBlock {block_height} mined with Nonce: {mined_header.nonce}")

        block_size = len(mined_header.serialize()) + sum(
            len(tx.serialize()) for tx in transactions
        )
        new_block = Block(
            block_height, block_size, mined_header, len(transactions), transactions
        )
        submission_payload = {
            "command": "submit_block",
            "params": {"block_hex": new_block.serialize().hex()},
        }
        submission_response = self.send_rpc_command(submission_payload, timeout=10)

        if submission_response and submission_response.get("status") == "success":
            print(
                f"Successfully submitted block {block_height}. Hash: {mined_header.generateBlockHash()}"
            )
        else:
            message = (
                submission_response.get("message", "Unknown error")
                if submission_response
                else "No response"
            )
            print(f"Failed to submit block: {message}")

    def run(self):
        print("Miner process started, waiting for work...")
        while True:
            response = self.send_rpc_command({"command": "get_work"})
            if not response:
                print(
                    "Could not get work: No response from daemon. Retrying in 5 seconds..."
                )
                time.sleep(5)
                continue

            if response.get("status") != "success":
                error_message = response.get("message", "Unknown error")
                print(
                    f"Could not get a valid work template. ERROR: {error_message}. Retrying in 5 seconds..."
                )
                time.sleep(5)
                continue

            template = response["template"]

            new_prev_hash = template["previous_block_hash"]
            transactions = [Tx.to_obj(tx_data) for tx_data in template["transactions"]]
            tx_ids = [bytes.fromhex(tx.id()) for tx in transactions]
            new_merkle_root = merkle_root(tx_ids)
            is_new_work = (
                new_prev_hash != self.current_work_prev_hash
                or new_merkle_root != self.current_work_merkle_root
            )
            if not is_new_work and self.mining_thread and self.mining_thread.is_alive():
                continue

            if self.mining_thread and self.mining_thread.is_alive():
                print(
                    "New work received (new block or txs), interrupting current mining task..."
                )
                self.stop_mining_event.set()
                self.mining_thread.join()

            self.current_work_prev_hash = new_prev_hash
            self.current_work_merkle_root = new_merkle_root

            block_header = BlockHeader(
                version=template["version"],
                prevBlockHash=bytes.fromhex(template["previous_block_hash"]),
                merkleRoot=new_merkle_root[::-1],
                timestamp=int(time.time()),
                bits=bytes.fromhex(template["bits"]),
                nonce=0,
            )

            print(
                f"New work received for block height {template['height']}. Starting mining..."
            )
            self.stop_mining_event.clear()

            self.mining_thread = Thread(
                target=self.mine_block_thread,
                args=(block_header, template["height"], transactions),
            )
            self.mining_thread.start()
