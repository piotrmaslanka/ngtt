from satella.coding import Closeable
from satella.coding.predicates import x
from satella.coding.sequences import index_of

from ..orders import Order

try:
    import ujson as json
except ImportError:
    import json
import typing as tp
import select
from satella.coding.concurrent import TerminableThread

from ..exceptions import DataStreamSyncFailed, ConnectionFailed
from ..protocol import NGTPHeaderType
from .connection import NGTTSocket


class NGTTConnection(TerminableThread):

    def __init__(self, cert_file: str, key_file: str,
                 on_new_order: tp.Callable[[Order], None]):
        super().__init__(name='ngtt uplink')
        self.on_new_order = on_new_order
        self.cert_file = cert_file
        self.key_file = key_file
        self.current_connection = None
        self.currently_running_ops = []  # type: tp.List[tp.Tuple[NGTPHeaderType, dict, Future]]
        self.op_id_to_op = {}   # type: tp.Dict[int, Future]

    def prepare(self) -> None:
        self.connect()

    def cleanup(self):
        if self.current_connection is not None:
            self.current_connection.close()
            self.current_connection = None

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

    def inner_loop(self):
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
        elif packet_type == NGTPHeaderType.ORDER:
            try:
                data = json.loads(data.decode('utf-8'))
            except ValueError:
                raise ConnectionFailed('Got invalid JSON')
            order = Order(data, tid, self.current_connection)
            self.on_new_order(order)
        elif packet_type in (NGTPHeaderType.DATA_STREAM_REJECT, NGTPHeaderType.DATA_STREAM_CONFIRM):
            if tid in self.op_id_to_op:
                # Assume it's a data stream running
                fut = self.op_id_to_op.pop(tid)

                index = index_of(x[2] == fut, self.currently_running_ops)
                del self.currently_running_ops[index]

                if packet_type == NGTPHeaderType.DATA_STREAM_CONFIRM:
                    fut.set_result(None)
                elif packet_type == NGTPHeaderType.DATA_STREAM_REJECT:
                    fut.set_exception(DataStreamSyncFailed())

    def loop(self) -> None:
        try:
            self.inner_loop()
        except ConnectionFailed:
            self.cleanup()
            self.connect()

    def add_op(self, op_type: NGTPHeaderType, data: tp.Union[dict, list]):
        pass

