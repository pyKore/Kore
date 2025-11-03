from src.utils.crypto_hash import hash256
from src.utils.serialization import bits_to_target, little_endian_to_int


def mine(block_header, stop_event):
    target = bits_to_target(block_header.bits)
    current_hash_int = target + 1

    while current_hash_int > target:
        if block_header.nonce % 100000 == 0 and stop_event.is_set():
            print("\nMining interrupted, new block found by another node")
            return None

        block_header.nonce += 1
        serialized_header = block_header.serialize()
        current_hash_bytes = hash256(serialized_header)
        current_hash_int = little_endian_to_int(current_hash_bytes)

        if block_header.nonce % 100000 == 0:
            print(
                f"Nonce: {block_header.nonce} | Hash: {current_hash_int:064x}",
                end="\r",
                flush=True,
            )

    print()
    block_header.blockHash = current_hash_bytes[::-1].hex()

    return block_header
