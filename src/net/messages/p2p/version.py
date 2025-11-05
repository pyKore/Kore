import time

from src.core.chain.chainparams import VERSION
from src.utils.crypto.serialization import int_to_little_endian, little_endian_to_int


class Version:
    command = b"version"

    def __init__(self, version=VERSION, start_height=0, timestamp=None):
        self.version = version
        self.start_height = start_height
        self.timestamp = timestamp or int(time.time())

    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += int_to_little_endian(self.start_height, 4)
        result += int_to_little_endian(self.timestamp, 8)
        return result

    @classmethod
    def parse(cls, s):
        version = little_endian_to_int(s.read(4))
        start_height = little_endian_to_int(s.read(4))
        timestamp = little_endian_to_int(s.read(8))
        return cls(version, start_height, timestamp)
