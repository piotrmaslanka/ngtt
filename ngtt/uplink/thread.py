from satella.coding.predicates import x
from satella.coding.sequences import index_of

from ngtt.ngtt.exceptions import DataStreamSyncFailed

try:
    import ujson as json
except ImportError:
    import json
import typing as tp
import select
from satella.coding.concurrent import TerminableThread

from ngtt.ngtt.protocol import NGTPHeaderType
from ngtt.ngtt.uplink.connection import NGTTSocket


class NGTTConnection(TerminableThread):

    def __init__(self, cert_file: str, key_file: str):
        super().__init__(name='ngtt uplink')
        self.cert_file = cert_file
        self.key_file = key_file
        self.current_connection = None
        self.currently_running_ops = [] # type: tp.List[tp.Tuple[NGTPHeaderType, dict, Future]]
        self.op_id_to_op = {}   # type: tp.Dict[int, Future]

    def connect(self):
        if self.current_connection is not None:
            return
        self.current_connection = NGTTSocket(self.cert_file, self.key_file)
        self.current_connection.connect()
        self.op_id_to_op = {}
        for h_type, data, fut in self.currently_running_ops:
            id_ = self.current_connection.id_assigner.allocate_int()
            self.current_connection.send_frame(id_, h_type, json.dumps(data).encode('utf-8'))
            self.op_id_to_op[id_] = fut

    def loop(self) -> None:
        self.current_connection.try_ping()
        rx = select.select([self.current_connection], [], [], timeout=5)[0]
        if not rx:
            return
        frame = self.current_connection.recv_frame()
        if frame is None:
            return
        tid, packet_type, data = frame
        if packet_type == NGTPHeaderType.PING:
            self.current_connection.got_ping()
        if tid in self.op_id_to_op:
            fut = self.op_id_to_op.pop(tid)
            if packet_type == NGTPHeaderType.DATA_STREAM_CONFIRM:
                fut.set_result(None)
            elif packet_type == NGTPHeaderType.DATA_STREAM_REJECT:
                fut.set_exception(DataStreamSyncFailed())

        index = index_of(x[2] == fut, self.currently_running_ops)
        del self.currently_running_ops[index]

    def add_op(self, op_type: NGTPHeaderType, data: tp.Union[dict, list]):
        pass

