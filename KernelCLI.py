import argparse
import json
import logging
import os
import shlex
import socket
import subprocess
import sys
import time
from cmd import Cmd

from src.chain.params import FEE_RATE_FAST, FEE_RATE_NORMAL, FEE_RATE_SLOW
from src.utils.config_loader import get_config_dict, load_config, update_config


class Colors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.WARNING, format="%(asctime)s [CLIENT-LOG] %(message)s"
)

running_processes = {"daemon": None, "miner": None}


def start_process_in_new_terminal(script_path, process_key):
    current_dir = os.getcwd()
    try:
        if sys.platform == "win32":
            os.system("")
            process = subprocess.Popen(
                f'start cmd /k "cd /d {current_dir} && {sys.executable} {script_path}"',
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        elif sys.platform == "darwin":
            script = f'tell app "Terminal" to do script "cd \\"{current_dir}\\" && \\"{sys.executable}\\" \\"{script_path}\\""'
            process = subprocess.Popen(
                ["osascript", "-e", script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        elif sys.platform.startswith("linux"):
            process = subprocess.Popen(
                ["gnome-terminal", "--", sys.executable, script_path],
                cwd=current_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            logger.error(
                f"Unsupported OS: {sys.platform}, please start {script_path} manually."
            )
            return None
    except Exception as e:
        logger.error(f"Failed to start new terminal for {process_key}: {e}")
        return None

    running_processes[process_key] = process
    logger.info(f"Started {process_key} in a new terminal")
    return process


def start_daemon(host, rpc_port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((host, rpc_port))
        logger.info("Kore Daemon is already running.")
        print(f"{Colors.OKGREEN}Kore Daemon is already running.{Colors.ENDC}")
        return None
    except (ConnectionRefusedError, socket.timeout):
        logger.info("Starting Kore Daemon...")
        print(f"{Colors.WARNING}Starting Kore Daemon...{Colors.ENDC}")
        daemon_script_path = os.path.join("src", "node", "koreD.py")
        return start_process_in_new_terminal(daemon_script_path, "daemon")


def shutdown_daemon(host, rpc_port):
    logger.info("Sending shutdown command to daemon...")
    response = send_rpc_command(host, rpc_port, {"command": "shutdown"})
    if response.get("status") == "success":
        logger.info(f"Daemon response: {response.get('message')}")
    else:
        logger.warning(f"Daemon shutdown error: {response.get('message')}")


def stop_miner_process():
    miner_process = running_processes.get("miner")
    if miner_process and miner_process.poll() is None:
        logger.info("Stopping local miner process...")
        miner_process.terminate()
        running_processes["miner"] = None
        print(f"{Colors.OKGREEN}Miner process stopped.{Colors.ENDC}")
    else:
        print(f"{Colors.WARNING}Miner process is not running.{Colors.ENDC}")


def send_rpc_command(host, rpc_port, command):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10.0)
            s.connect((host, rpc_port))
            s.sendall(json.dumps(command).encode("utf-8"))

            response_data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response_data += chunk

            return json.loads(response_data.decode("utf-8"))

    except ConnectionRefusedError:
        return {
            "status": "error",
            "message": f"Connection refused. Is kored running on {host}:{rpc_port}?",
        }
    except socket.timeout:
        return {
            "status": "error",
            "message": "Connection timed out. Daemon is unresponsive.",
        }
    except Exception as e:
        return {"status": "error", "message": f"RPC Error: {e}"}


class KoreCLI(Cmd):

    _logo_printed = False

    def __init__(self):
        super().__init__()
        self.host = "127.0.0.1"
        self.rpc_port = 8002
        self.daemon_process = None
        self.load_client_config()

    def load_client_config(self):
        try:
            config = load_config()
            self.host = config.get("NETWORK", "host", fallback="127.0.0.1")
            self.rpc_port = int(config.get("API", "port", fallback=8001)) + 1
        except Exception as e:
            logger.error(f"Failed to load config.ini: {e}")
            print(
                f"{Colors.FAIL}Warning:{Colors.ENDC} Could not load config.ini. Using defaults"
            )

    def preloop(self):
        if not self._logo_printed:
            self.print_logo()
            self._logo_printed = True

        print(
            f"Attempting to connect to daemon at {Colors.OKCYAN}{self.host}:{self.rpc_port}{Colors.ENDC}"
        )
        self.daemon_process = start_daemon(self.host, self.rpc_port)

        retries = 5
        connected = False
        print("Waiting for daemon response...", end="", flush=True)
        while retries > 0:
            response = send_rpc_command(self.host, self.rpc_port, {"command": "ping"})
            if response.get("status") == "success":
                connected = True
                break
            print(f".", end="", flush=True)
            time.sleep(1)
            retries -= 1

        if connected:
            print(
                f"\n{Colors.OKGREEN}Connection successful{Colors.ENDC} \nWelcome to Kore CLI !"
            )
            print("Type 'help' or '?' for a list of commands\n")
            self.prompt = (
                f"{Colors.BOLD}{Colors.OKCYAN}(kore@{self.host}){Colors.ENDC} "
            )
        else:
            print(f"\n{Colors.FAIL}Failed to connect to daemon{Colors.ENDC}")
            print("Please check config.ini or start koreD.py manually")
            self.prompt = f"{Colors.BOLD}{Colors.FAIL}(kore-offline){Colors.ENDC} "

    def postloop(self):
        print(f"\n{Colors.WARNING}Shutting down client...{Colors.ENDC}")
        stop_miner_process()
        if self.daemon_process:
            shutdown_daemon(self.host, self.rpc_port)
            time.sleep(1)
            if self.daemon_process.poll() is None:
                self.daemon_process.terminate()
            logger.info("Daemon process stopped by client")
        print("Goodbye")

    def print_logo(self):
        print(
            f"{Colors.BOLD}{Colors.OKCYAN}"
            "██╗  ██╗███████╗██████╗ ███╗   ██╗███████╗██╗\n"
            "██║ ██╔╝██╔════╝██╔══██╗████╗  ██║██╔════╝██║\n"
            "█████╔╝ █████╗  ██████╔╝██╔██╗ ██║█████╗  ██║\n"
            "██╔═██╗ ██╔══╝  ██╔══██╗██║╚██╗██║██╔══╝  ██║\n"
            "██║  ██╗███████╗██║  ██║██║ ╚████║███████╗███████╗\n"
            "╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝\n"
            f"{Colors.ENDC}"
        )

    def rpc_call(self, command):
        response = send_rpc_command(self.host, self.rpc_port, command)
        if response and response.get("status") == "success":
            return response
        elif response:
            print(
                f"{Colors.FAIL}Error:{Colors.ENDC} {response.get('message', 'Unknown error')}"
            )
            return None
        else:
            print(f"{Colors.FAIL}Error:{Colors.ENDC} Failed to communicate with daemon")
            return None

    def do_help(self, arg):
        print(f"\n{Colors.BOLD}Kore CLI Help Menu{Colors.ENDC}")
        print(
            "Type a command and press Enter. Most commands support guided mode (no arguments)"
        )
        print("-" * 60)
        cmds = {
            "send [from] [to] [amount]": "Send KOR to a specified address",
            "createwallet [name]": "Create a new wallet",
            "listwallets": "List all wallets and their balances",
            "startminer": "Starts the miner process (KoreX)",
            "stopminer": "Stops the miner process",
            "getmempool": "List all transactions in the mempool",
            "getheight": "Get the current blockchain height",
            "getconfig": "Display the current config settings",
            "getinfo": "Display informations about node's status",
            "settings": "Open a menu to edit your config",
            "ping": "Check connection with the daemon",
            "help": "Show help menu",
            "clear": "Clear the terminal screen",
            "exit": "Exit the Kore CLI and shutdown the daemon",
        }
        for cmd, desc in cmds.items():
            print(f"  {Colors.OKCYAN}{cmd:<28}{Colors.ENDC} {desc}")
        print()

    def do_getinfo(self, arg):
        print(f"{Colors.WARNING}Fetching node info...{Colors.ENDC}", end="\r")
        response = self.rpc_call({"command": "getinfo"})
        sys.stdout.write(" " * 30 + "\r")
        if response:
            info = response.get("info", {})
            height = info.get("height", "N/A")
            mempool = info.get("mempool_size", "N/A")
            wallets = info.get("wallet_count", "N/A")

            print(f"\n  {Colors.BOLD}--- Kore Node Status ---{Colors.ENDC}")
            print(
                f"  {Colors.OKCYAN}Host:{Colors.ENDC}         {self.host}:{self.rpc_port}"
            )
            print(
                f"  {Colors.OKCYAN}Block Height:{Colors.ENDC} {Colors.WARNING}{height}{Colors.ENDC}"
            )
            print(f"  {Colors.OKCYAN}Mempool Txs:{Colors.ENDC}  {mempool}")
            print(f"  {Colors.OKCYAN}Wallets Loaded:{Colors.ENDC} {wallets}")
            print(f"  {Colors.BOLD}--------------------------{Colors.ENDC}\n")

    def do_ping(self, arg):
        print(f"{Colors.WARNING}Pinging daemon...{Colors.ENDC}", end="\r")
        response = self.rpc_call({"command": "ping"})
        sys.stdout.write(" " * 20 + "\r")
        if response:
            print(
                f"{Colors.OKGREEN}Pong!{Colors.ENDC} Daemon is responsive (Message: {response.get('message')})"
            )

    def do_getheight(self, arg):
        print(f"{Colors.WARNING}Fetching height...{Colors.ENDC}", end="\r")
        response = self.rpc_call({"command": "get_chain_height"})
        sys.stdout.write(" " * 20 + "\r")
        if response:
            print(
                f"Current Block Height: {Colors.BOLD}{Colors.WARNING}{response.get('height')}{Colors.ENDC}"
            )

    def do_listwallets(self, arg):
        print(f"{Colors.WARNING}Fetching wallets...{Colors.ENDC}", end="\r")
        response = self.rpc_call({"command": "get_wallets"})
        sys.stdout.write(" " * 20 + "\r")
        if response:
            wallets = response.get("wallets", [])
            if not wallets:
                print(
                    f"{Colors.WARNING}No wallets found.{Colors.ENDC} Use 'createwallet <name>' to create one"
                )
                return

            print(f"\n{Colors.BOLD}Found {len(wallets)} wallet(s):{Colors.ENDC}")
            header = f"{'Name':<20} | {'Balance (KOR)':>18} | {'Address':<40}"
            print(Colors.BOLD + header + Colors.ENDC)
            print("-" * len(header))
            for wallet in wallets:
                name = wallet.get("WalletName", "N/A")
                balance = f"{wallet.get('balance', 0.0):.8f}"
                address = wallet.get("PublicAddress", "N/A")
                print(
                    f"{name:<20} | {Colors.OKGREEN}{balance:>18}{Colors.ENDC} | {Colors.OKCYAN}{address:<40}{Colors.ENDC}"
                )
            print()

    def do_createwallet(self, arg):
        try:
            args = shlex.split(arg)
            if not args:
                name = input(f"Enter a name for the new wallet: ")
            else:
                name = args[0]

            if not name:
                print(f"{Colors.FAIL}Error:{Colors.ENDC} Wallet name cannot be empty")
                return

            command = {"command": "create_wallet", "params": {"name": name}}

            print(f"{Colors.WARNING}Creating wallet '{name}'...{Colors.ENDC}", end="\r")
            response = self.rpc_call(command)
            sys.stdout.write(" " * 30 + "\r")

            if response:
                wallet = response.get("wallet", {})
                print(f"\n{Colors.OKGREEN}{'=' * 60}{Colors.ENDC}")
                print(f"{Colors.BOLD} Wallet created successfully:{Colors.ENDC}")
                print(
                    f"  Name:    {Colors.OKCYAN}{wallet.get('WalletName')}{Colors.ENDC}"
                )
                print(
                    f"  Address: {Colors.OKCYAN}{wallet.get('PublicAddress')}{Colors.ENDC}"
                )
                print(f"\n  {Colors.FAIL}{Colors.BOLD}PRIVATE KEY{Colors.ENDC}")
                print(f"  {Colors.FAIL}{wallet.get('privateKey')}{Colors.ENDC}")
                print(f"  (Please don't share your private key with anyone")
                print(f"{Colors.OKGREEN}{'=' * 60}{Colors.ENDC}\n")

        except Exception as e:
            print(f"{Colors.FAIL}An error occurred:{Colors.ENDC} {e}")

    def do_send(self, arg):
        parser = argparse.ArgumentParser(prog="send", exit_on_error=False)
        parser.add_argument(
            "from_addr", nargs="?", help="The public address to send from"
        )
        parser.add_argument(
            "to_addr", nargs="?", help="The public address of the recipient"
        )
        parser.add_argument(
            "amount", nargs="?", help="The amount of KOR to send (e.g., 10.5)"
        )
        parser.add_argument(
            "--fee",
            choices=["slow", "normal", "fast"],
            default="normal",
            help="Transaction fee rate (slow, normal, fast)",
        )

        try:
            if not arg:
                print("--- New Transaction ---")
                from_addr = input(
                    f"From Address ({Colors.OKCYAN}kY6uY...{Colors.ENDC}): "
                )
                to_addr = input(
                    f"To Address   ({Colors.OKCYAN}kY6uY...{Colors.ENDC}): "
                )
                amount_str = input(f"Amount (KOR)  : ")
                fee_choice = (
                    input(
                        f"Fee (slow, normal, fast) [{Colors.WARNING}normal{Colors.ENDC}]: "
                    )
                    or "normal"
                )

                args = argparse.Namespace(
                    from_addr=from_addr,
                    to_addr=to_addr,
                    amount=amount_str,
                    fee=fee_choice,
                )
            else:
                args = parser.parse_args(shlex.split(arg))

            amount_float = float(args.amount)
            if amount_float <= 0:
                print(
                    f"{Colors.FAIL}Error:{Colors.ENDC} Amount must be a positive number"
                )
                return

            fee_map = {
                "slow": FEE_RATE_SLOW,
                "normal": FEE_RATE_NORMAL,
                "fast": FEE_RATE_FAST,
            }
            fee_rate = fee_map.get(args.fee.lower(), FEE_RATE_NORMAL)

            print("\n--- Confirm Transaction ---")
            print(f"  From:   {Colors.OKCYAN}{args.from_addr}{Colors.ENDC}")
            print(f"  To:     {Colors.OKCYAN}{args.to_addr}{Colors.ENDC}")
            print(
                f"  Amount: {Colors.OKGREEN}{Colors.BOLD}{amount_float} KOR{Colors.ENDC}"
            )
            print(
                f"  Fee:    {Colors.WARNING}{args.fee} ({fee_rate} kores/b){Colors.ENDC}"
            )

            confirm = input(
                f"\nAre you sure you want to send this transaction? (y/n): "
            )
            if confirm.lower() != "y":
                print(f"{Colors.WARNING}Transaction cancelled.{Colors.ENDC}\n")
                return

            command = {
                "command": "send_tx",
                "params": {
                    "from": args.from_addr,
                    "to": args.to_addr,
                    "amount": amount_float,
                    "fee_rate": fee_rate,
                },
            }

            print(
                f"{Colors.WARNING}Submitting transaction to daemon...{Colors.ENDC}",
                end="\r",
            )
            response = self.rpc_call(command)
            sys.stdout.write(" " * 40 + "\r")

            if response:
                print(f"{Colors.OKGREEN}Transaction sent successfully!{Colors.ENDC}")
                print(f"  TXID: {Colors.OKCYAN}{response.get('txid')}{Colors.ENDC}\n")

        except (argparse.ArgumentError, SystemExit):
            print(
                f"{Colors.FAIL}Invalid arguments.{Colors.ENDC} Usage: send [from] [to] [amount] [--fee=normal]"
            )
        except ValueError:
            print(f"{Colors.FAIL}Error:{Colors.ENDC} Amount must be a valid number")
        except Exception as e:
            print(f"{Colors.FAIL}An error occurred:{Colors.ENDC} {e}")

    def do_getmempool(self, arg):
        print(f"{Colors.WARNING}Fetching mempool...{Colors.ENDC}", end="\r")
        response = self.rpc_call({"command": "get_mempool"})
        sys.stdout.write(" " * 20 + "\r")

        if response:
            mempool_txs = response.get("mempool", [])
            if not mempool_txs:
                print(f"{Colors.WARNING}Mempool is empty{Colors.ENDC}")
                return

            print(
                f"\n{Colors.BOLD}Mempool has {len(mempool_txs)} transaction(s):{Colors.ENDC}"
            )
            header = f"{'Hash':<40} | {'Value (KOR)':>15} | {'Fee (kores)':>15}"
            print(Colors.BOLD + header + Colors.ENDC)
            print("-" * len(header))

            mempool_txs.sort(key=lambda x: x.get("receivedTime", 0), reverse=True)

            for tx in mempool_txs:
                tx_hash_short = tx.get("hash", "N/A")[:37] + "..."
                value = f"{tx.get('value', 0.0):.8f}"
                fee = tx.get("fee", 0)
                print(
                    f"{Colors.OKCYAN}{tx_hash_short:<40}{Colors.ENDC} | {Colors.OKGREEN}{value:>15}{Colors.ENDC} | {Colors.WARNING}{fee:>15}{Colors.ENDC}"
                )
            print()

    def do_startminer(self, arg):
        if running_processes.get("miner") and running_processes["miner"].poll() is None:
            print(f"{Colors.WARNING}Miner process is already running{Colors.ENDC}")
            return

        print("Starting KoreX miner process in a new window...")
        miner_script_path = os.path.join("KoreX", "main.py")
        if os.path.exists(miner_script_path):
            start_process_in_new_terminal(miner_script_path, "miner")
            print(f"{Colors.OKGREEN}Miner process launched.{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}Error:{Colors.ENDC} KoreX/main.py not found")

    def do_stopminer(self, arg):
        stop_miner_process()

    def do_getconfig(self, arg):
        try:
            config_dict = get_config_dict()
            print(f"\n{Colors.BOLD}Current Configuration:{Colors.ENDC}")
            for section, options in config_dict.items():
                print(f"\n  [{Colors.OKCYAN}{section}{Colors.ENDC}]")
                if not options:
                    print(f"    {Colors.WARNING}(Empty){Colors.ENDC}")
                    continue
                for key, value in options.items():
                    print(f"    {key:<12} = {Colors.WARNING}{value}{Colors.ENDC}")
            print()
        except Exception as e:
            print(f"{Colors.FAIL}Error reading config file:{Colors.ENDC} {e}")

    def do_settings(self, arg):
        restart_needed = False
        print(f"\n{Colors.BOLD}--- Settings Menu ---{Colors.ENDC}")
        print(f"Modifying these settings will update the config file")

        while True:
            try:
                current_config = get_config_dict()
                c_host = current_config.get("NETWORK", {}).get("host", "N/A")
                c_p2p_port = current_config.get("P2P", {}).get("port", "N/A")
                c_api_port = current_config.get("API", {}).get("port", "N/A")
                c_wallet = current_config.get("MINING", {}).get("wallet", "N/A")
            except Exception as e:
                print(f"{Colors.FAIL}Error reading config:{Colors.ENDC} {e}")
                return

            print("\n" + "=" * 40)
            print(
                f"1 - Change Host IP        ({Colors.OKCYAN}current: {c_host}{Colors.ENDC})"
            )
            print(
                f"2 - Change P2P Port       ({Colors.OKCYAN}current: {c_p2p_port}{Colors.ENDC})"
            )
            print(
                f"3 - Change API Port       ({Colors.OKCYAN}current: {c_api_port}{Colors.ENDC})"
            )
            print(
                f"4 - Set Miner Wallet      ({Colors.OKCYAN}current: {c_wallet}{Colors.ENDC})"
            )
            print(f"5 - {Colors.WARNING}Back to main menu{Colors.ENDC}")
            choice = input("Enter your choice (1-5): ")

            if choice == "1":
                new_host = input(f"Enter new host IP [current: {c_host}]: ") or c_host
                update_config("NETWORK", "host", new_host)
                print(f"{Colors.OKGREEN}Host IP updated to {new_host}.{Colors.ENDC}")
                restart_needed = True
            elif choice == "2":
                new_port = (
                    input(f"Enter new P2P port [current: {c_p2p_port}]: ") or c_p2p_port
                )
                update_config("P2P", "port", new_port)
                print(f"{Colors.OKGREEN}P2P port updated to {new_port}.{Colors.ENDC}")
                restart_needed = True
            elif choice == "3":
                new_port = (
                    input(f"Enter new API port [current: {c_api_port}]: ") or c_api_port
                )
                update_config("API", "port", new_port)
                print(f"{Colors.OKGREEN}API port updated to {new_port}.{Colors.ENDC}")
                restart_needed = True
            elif choice == "4":
                print(f"{Colors.WARNING}Fetching wallets...{Colors.ENDC}", end="\r")
                response = self.rpc_call({"command": "get_wallets"})
                sys.stdout.write(" " * 20 + "\r")  # Efface

                if not response or not response.get("wallets"):
                    print(
                        f"{Colors.WARNING}No wallets found. Create one first with 'createwallet'{Colors.ENDC}"
                    )
                    continue

                wallets = response.get("wallets", [])
                print("\nAvailable wallets:")
                header = f"{'Num':<4} | {'Name':<20} | {'Address':<40}"
                print(Colors.BOLD + header + Colors.ENDC)
                print("-" * len(header))
                for i, wallet in enumerate(wallets):
                    print(
                        f"{Colors.BOLD}{i + 1:<4}{Colors.ENDC} | {Colors.OKCYAN}{wallet.get('WalletName'):<20}{Colors.ENDC} | {wallet.get('PublicAddress')}"
                    )

                try:
                    wallet_choice = input(
                        f"\nSelect a wallet number [current: {c_wallet}]: "
                    )
                    if not wallet_choice.isdigit() or not (
                        0 < int(wallet_choice) <= len(wallets)
                    ):
                        print(f"{Colors.FAIL}Invalid selection.{Colors.ENDC}")
                        continue

                    selected_wallet_name = wallets[int(wallet_choice) - 1]["WalletName"]
                    update_config("MINING", "wallet", selected_wallet_name)
                    print(
                        f"{Colors.OKGREEN}Miner wallet updated to {selected_wallet_name}{Colors.ENDC}"
                    )
                except (ValueError, IndexError):
                    print(f"{Colors.FAIL}Invalid input{Colors.ENDC}")
            elif choice == "5":
                break
            else:
                print(
                    f"{Colors.FAIL}Invalid choice. Please enter a number from 1 to 5{Colors.ENDC}"
                )

        if restart_needed:
            print(
                f"\n{Colors.BOLD}{Colors.WARNING}--- RESTART REQUIRED ---{Colors.ENDC}"
            )
            print(f"Network settings (host/port) have been changed")
            print(
                f"Please type '{Colors.OKCYAN}exit{Colors.ENDC}' to shutdown and restart both the daemon and client"
            )

    def do_clear(self, arg):
        os.system("cls" if os.name == "nt" else "clear")
        self.print_logo()
        print("Type 'help' or '?' for a list of commands.\n")

    def do_quit(self, arg):
        return True

    def do_exit(self, arg):
        return self.do_quit(arg)

    def do_EOF(self, arg):
        print("exit")
        return self.do_quit(arg)

    def emptyline(self):
        pass


if __name__ == "__main__":
    if sys.platform == "win32":
        os.system("")

    cli_instance = KoreCLI()
    try:
        cli_instance.cmdloop()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Caught interrupt (Ctrl+C).{Colors.ENDC}")
        try:
            confirm = input("  Do you want to shut down the daemon and exit? (y/n): ")
            if confirm.lower() == "y":
                cli_instance.postloop()
            else:
                print("\nExiting client. The daemon is still running")
        except EOFError:
            print("\nExiting")
            cli_instance.postloop()
    except Exception as e:
        print(f"\n{Colors.FAIL}An unexpected client error occurred:{Colors.ENDC} {e}")
        logger.error("CLI main loop crashed", exc_info=True)
        cli_instance.postloop()
