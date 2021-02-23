import typing as tp
import struct

from satella.coding.structures import HashableIntEnum
from .exceptions import InvalidFrame

class NGTPHeaderType(HashableIntEnum):
    PING = 0
    ORDER = 1
    ORDER_CONFIRM = 2
    LOGS = 3
    DATA_STREAM = 4
    DATA_STREAM_CONFIRM = 5
    DATA_STREAM_REJECT = 6


STRUCT_LHH = struct.Struct('>LHH')


class NGTTFrame:
    def __init__(self, tid: int, packet_type: NGTPHeaderType, data: bytes):
        self.tid = tid
        self.packet_type = packet_type
        self.data = data

    def __len__(self):
        return STRUCT_LHH.size + len(self.data)

    def __bytes__(self):
        return STRUCT_LHH.pack(len(self.data), self.tid, self.packet_type.value)

    @classmethod
    def from_bytes(cls, b: tp.Union[bytes, bytearray]) -> 'NGTTFrame':
        lne, tid, htype = STRUCT_LHH.unpack(b[:STRUCT_LHH.size])

def env_to_hostname(env: int) -> str:
    if env == 0:
        return 'api.smok.co'
    elif env == 1:
        return 'api.test.smok-serwis.pl'
    else:
        return 'http-api'
