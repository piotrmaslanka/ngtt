import ssl
import typing as tp
import os
import socket
import struct

import tempfile
from ssl import SSLContext, PROTOCOL_TLS_CLIENT, SSLError

from satella.coding import silence_excs
from satella.coding.concurrent import IDAllocator
from satella.files import read_in_file
from ..protocol import NGTPHeaderType, STRUCT_LHH, env_to_hostname
from .certificates import get_device_info, get_dev_ca_cert, get_root_cert


class ConnectionFailed(Exception):
    pass


class NGTTSocket:
    def __init__(self, device: 'SMOKDevice', cert_file: str, key_file: str):
        self.environment = get_device_info(read_in_file(cert_file))[1]
        self.host = env_to_hostname(self.environment)
        self.device = device
        self.cert_file = cert_file
        self.key_file = key_file
        self.socket = None
        self.buffer = bytearray()
        self.w_buffer = bytearray()
        self.socket.setblocking(False)

        with tempfile.NamedTemporaryFile('w', delete=False) as chain_file:
            chain_file.write(read_in_file(self.cert_file))
            chain_file.write(get_dev_ca_cert())
            chain_file.write(get_root_cert())
        self.chain_file_name = chain_file.name
        self.id_assigner = IDAllocator(start_at=1)

    @silence_excs(ssl.SSLWantWriteError)
    def send_frame(self, tid: int, header: NGTPHeaderType, data: bytes):
        """
        Schedule a frame to be sent

        :param tid: transaction ID
        :param header: packet type
        :param data: data to send
        """
        self.w_buffer.extend(STRUCT_LHH.pack(len(data, tid, header.value)))
        self.w_buffer.extend(data)
        data_sent = self.socket.send(self.w_buffer)
        del self.w_buffer[:data_sent]

    @silence_excs(ssl.SSLWantWriteError)
    def try_send(self):
        """
        Try to send some data
        """
        if self.w_buffer:
            try:
                data_sent = self.socket.send(self.w_buffer)
                del self.w_buffer[:data_sent]
            except socket.timeout:
                return

    @silence_excs(ssl.SSLWantReadError)
    def recv_frame(self) -> tp.Optional[tp.Tuple[int, NGTPHeaderType, bytes]]:
        """
        Receive a frame from remote socket

        :return: a tuple of transaction ID, header type, data
        """
        data = self.socket.recv(512)
        if not data:
            raise ConnectionFailed()
        self.buffer.extend(data)
        if len(self.buffer) > STRUCT_LHH.size:
            tid, h_type, length = STRUCT_LHH.unpack(self.buffer[:STRUCT_LHH.size])
            if len(self.buffer) < STRUCT_LHH.size + length:
                return None
            data = self.buffer[STRUCT_LHH.size:STRUCT_LHH.size+length]
            del self.buffer[:STRUCT_LHH.size+length]
            return tid, NGTPHeaderType(h_type), data

    def __del__(self):
        os.unlink(self.chain_file_name)

    def disconnect(self):
        """
        Disconnect from the remote host
        """
        if self.socket is not None:
            self.socket.close()
            self.socket = None

    def connect(self):
        """
        Connect to remote host

        :raises SSLError: an error occurred
        """
        if self.socket is not None:
            return
        ssl_context = SSLContext(PROTOCOL_TLS_CLIENT)
        ssl_context.load_verify_locations(cadata=get_root_cert().encode('utf-8'))
        ssl_context.load_cert_chain(self.chain_file_name, self.key_file)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = ssl_context.wrap_socket(sock, server_hostname=self.host)
        try:
            ssl_sock.connect((self.host, 2408))
            ssl_sock.do_handshake()
            self.socket = ssl_sock
        except (socket.error, SSLError):
            raise ConnectionFailed()

