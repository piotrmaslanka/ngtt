from concurrent.futures import Future

from satella.coding import Closeable, wraps, silence_excs
from satella.coding.decorators import retry
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
from ..protocol import NGTTHeaderType
from .connection import NGTTSocket


def must_be_connected(fun):
    @wraps(fun)
    def outer(self, *args, **kwargs):
        if self.current_connection is None:
            self.connect()
        return fun(self, *args, **kwargs)
    return outer


class NGTTConnection(TerminableThread):

    def __init__(self, cert_file: str, key_file: str,
                 on_new_order: tp.Callable[[Order], None]):
        super().__init__(name='ngtt uplink')
        self.on_new_order = on_new_order
        self.cert_file = cert_file
        self.key_file = key_file
        self.current_connection = None
        self.currently_running_ops = []  # type: tp.List[tp.Tuple[NGTTHeaderType, bytes, Future]]
        self.op_id_to_op = {}   # type: tp.Dict[int, Future]

    def prepare(self) -> None:
        while not self._terminating:
            with silence_excs(ConnectionFailed):
                self.connect()

    def stop(self, wait_for_completion: bool = True):
        """
        Stop this thread and the connection

        :param wait_for_completion: whether to wait for thread to terminate
        """
        self.terminate()
        if wait_for_completion:
            self.join()

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
            self.current_connection.send_frame(id_, h_type, data)
            self.op_id_to_op[id_] = fut

    @must_be_connected
    def sync_pathpoints(self, data: tp.List) -> Future:
        """
        Try to synchronize pathpoints.

        This will survive multiple reconnection attempts.

        :param data: exactly the same thing that you would submit to POST
        at POST https://api.smok.co/v1/device/
        :return: a Future telling you whether this succeeds or fails
        """
        fut = Future()
        fut.set_running_or_notify_cancel()
        tid = self.current_connection.id_assigner.allocate_int()
        data = json.dumps(data).encode('utf-8')
        self.currently_running_ops.append((NGTTHeaderType.DATA_STREAM, data, fut))
        self.current_connection.send_frame(tid, NGTTHeaderType.DATA_STREAM, data)
        self.op_id_to_op[tid] = fut
        return fut

    def inner_loop(self):
        self.current_connection.try_ping()
        rx = select.select([self.current_connection], [], [], timeout=5)[0]
        if not rx:
            return
        frame = self.current_connection.recv_frame()
        if frame is None:
            return
        tid, packet_type, data = frame
        if packet_type == NGTTHeaderType.PING:
            self.current_connection.got_ping()
        elif packet_type == NGTTHeaderType.ORDER:
            try:
                data = json.loads(data.decode('utf-8'))
            except ValueError:
                raise ConnectionFailed('Got invalid JSON')
            order = Order(data, tid, self.current_connection)
            self.on_new_order(order)
        elif packet_type in (NGTTHeaderType.DATA_STREAM_REJECT, NGTTHeaderType.DATA_STREAM_CONFIRM):
            if tid in self.op_id_to_op:
                # Assume it's a data stream running
                fut = self.op_id_to_op.pop(tid)

                index = index_of(x[2] == fut, self.currently_running_ops)
                del self.currently_running_ops[index]

                if packet_type == NGTTHeaderType.DATA_STREAM_CONFIRM:
                    fut.set_result(None)
                elif packet_type == NGTTHeaderType.DATA_STREAM_REJECT:
                    fut.set_exception(DataStreamSyncFailed())
        elif packet_type == NGTTHeaderType.SYNC_BAOB_RESPONSE:
            if tid in self.op_id_to_op:
                fut = self.op_id_to_op.pop(tid)

                index = index_of(x[2] == fut, self.currently_running_ops)
                del self.currently_running_ops[index]

                fut.set_result(json.loads(data.decode('utf8')))

    def loop(self) -> None:
        try:
            self.inner_loop()
        except ConnectionFailed:
            self.cleanup()
            self.connect()

    @must_be_connected
    def sync_baobs(self, baobs: tp.Dict[str, int]) -> Future:
        """
        Request to synchronize BAOBs

        :param baobs: a dictionary of locally kept BAOB name => local version
        :return: a Future that will receive a result of dict
        {"download": [.. list of BAOBs to download from the server ..],
         "upload": [.. list of BAOBs to upload to the server ..]}
        """
        fut = Future()
        fut.set_running_or_notify_cancel()
        tid = self.current_connection.id_assigner.allocate_int()
        data = json.dumps(baobs).encode('utf-8')
        self.currently_running_ops.append((NGTTHeaderType.SYNC_BAOB_REQUEST, data, fut))
        self.current_connection.send_frame(tid, NGTTHeaderType.SYNC_BAOB_REQUEST, data)
        self.op_id_to_op[tid] = fut
        return fut

    @must_be_connected
    def stream_logs(self, data: tp.List) -> None:
        """
        Stream logs to the server

        This will work on a best-effort basis.

        :param data: the same thing that you would PUT /v1/device/device_logs
        """
        data = json.dumps(data).encode('utf-8')
        self.current_connection.send_frame(0, NGTTHeaderType.LOGS, data)


