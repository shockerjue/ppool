#!/usr/bin/python
# -*- coding: UTF-8 -*-

import sys
import socket
import pickle
import struct
import logging
import traceback

sys.path.append(".")
sys.path.append("..")
from ppool.common import HeaderSize
from ppool.common import PacketSize
from ppool.common import Packet
from ppool.object import Object

logger = logging.getLogger(__name__)


class Caller(Object):
    def __init__(self, uri=()) -> None:
        super().__init__()

        self._uri = uri
        self.connect = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect.connect(self._uri)
        self.buffer = bytes()
        self._name = "Caller"

        logger.info("Caller is success!  uri={}".format(self._uri))
        pass

    def _to_excutor(self, pkt: Packet):
        if pkt is None:
            return

        body = pickle.dumps(pkt)
        msg_len_bs = struct.pack("i", len(body))
        self.connect.sendall(msg_len_bs + body)
        return

    def release(self):
        logger.info("Caller release is sucess, uri={}".format(self._uri))

        if self.connect is not None:
            self.connect.close()

        return

    def apply(self, pkt: Packet, timeout=5):
        if pkt is None:
            return None

        self.connect.settimeout(timeout)
        self._to_excutor(pkt=pkt)

        while True:
            try:
                data = self.connect.recv(PacketSize)
                if data is None:
                    logger.warning("apply - recv return is None")

                    continue

                if data == b"":
                    break

                self.buffer = self.buffer + data
                if 4 > len(self.buffer):
                    logger.warning(
                        "apply - The header length of the read packet is less than 4 bytes, and the actual length is {}. ".format(
                            len(self.buffer)
                        )
                    )

                    continue

                # Read head from packet
                bs_msg_len = self.buffer[:HeaderSize]
                bs_len = struct.unpack("i", bs_msg_len)[0]

                if bs_len > len(self.buffer[HeaderSize:]):
                    logger.warning(
                        "apply - The data has not been received yet, the total size is {} bytes, and now only {} bytes are received.".format(
                            bs_len, len(self.buffer[HeaderSize:])
                        )
                    )

                    continue

                # Read data from packet
                ppos = bs_len + HeaderSize
                data = self.buffer[HeaderSize:ppos]
                self.buffer = self.buffer[ppos:]

                return pickle.loads(data)
            except socket.timeout as e:
                logger.error(
                    "apply apply is error, e={}   trace={}".format(
                        e, traceback.format_exc()
                    )
                )
                raise Exception("apply call timeout occurred!")

        return None
