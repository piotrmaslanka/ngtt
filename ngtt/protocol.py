import struct

from satella.coding.structures import HashableIntEnum


class NGTPHeaderType(HashableIntEnum):
    PING = 0
    ORDER = 1
    ORDER_CONFIRM = 2
    LOGS = 3
    DATA_STREAM = 4
    DATA_STREAM_CONFIRM = 5
    DATA_STREAM_REJECT = 6


STRUCT_LHH = struct.Struct('>LHH')


def env_to_hostname(env: int) -> str:
    if env == 0:
        return 'api.smok.co'
    elif env == 1:
        return 'api.test.smok-serwis.pl'
    else:
        return 'http-api'
