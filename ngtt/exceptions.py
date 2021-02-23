class NGTTError(Exception):
    pass


class ConnectionFailed(NGTTError):
    pass


class DataStreamSyncFailed(NGTTError):
    pass


class InvalidFrame(NGTTError):
    pass
