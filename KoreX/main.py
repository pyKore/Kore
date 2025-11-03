import json
import os
import socket
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from KernelX.miner import Miner
from src.utils.config_loader import load_config


def main():
    config = load_config()
    host = config["NETWORK"]["host"]
    rpc_port = int(config["API"]["port"]) + 1

    print("--- KernelX Miner ---")
    print(f"Connecting to Kernel daemon at {host}:{rpc_port}")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((host, rpc_port))
            s.sendall(json.dumps({"command": "ping"}).encode("utf-8"))
            response_data = s.recv(1024)
            response = json.loads(response_data.decode("utf-8"))
            if response.get("message") != "pong":
                print("Daemon responded unexpectedly, please check daemon status")
                return
    except (socket.timeout, ConnectionRefusedError) as e:
        print(f"Connection failed: {e}. Please ensure the Kernel daemon is running")
        return

    print("Connection successful. Starting miner...")

    miner = Miner(host, rpc_port)
    miner.run()


if __name__ == "__main__":
    main()
