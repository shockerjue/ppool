#!/usr/bin/python
# -*- coding: UTF-8 -*-

import sys
import time
import threading
import queue
import socket
import pickle
import struct
import traceback
import logging
from multiprocessing import Process
from typing import Union

sys.path.append(".")
sys.path.append("..")
from ppool.common import Packet
from ppool.common import HeaderSize
from ppool.common import PacketSize
from ppool.object import Object
from ppool.context import Context

logger = logging.getLogger(__name__)


class Excutor(Process, Object):
    def __init__(
        self,
        uri=(),
        func=None,
        ctx: Union[Context, None] = None,
    ):
        Process.__init__(self, daemon=False)
        super().__init__()

        self._uri, self.func = uri, func
        self.connect, self.server = None, None
        self.tid, self.addr = None, None
        self._name = "Excutor"
        self.ctx = ctx

        return

    def release(self):
        if self.connect is not None:
            self.connect.close()

        if self.server is not None:
            self.server.close()

        self.tid._stop() if self.tid is not None else None
        logger.info(
            "Excutor release is sucess ----> address:{} pid:{}".format(
                self.addr, self.pid
            )
        )
        return

    def wait_connect(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(self._uri)
        self.server.listen(1)

        self.connect, self.addr = self.server.accept()
        return

    def start_service(self):
        self.pqueue = queue.Queue(maxsize=1)
        self.tid = threading.Thread(
            target=Excutor.obtain_prerocess,
            args=(
                self.pqueue,
                self.connect,
            ),
        ).start()

        return

    @staticmethod
    def obtain_prerocess(pqueue: queue.Queue = None, connect=None):
        if connect is None:
            return

        buffer = bytes()
        while True:
            data = None
            try:
                data = connect.recv(PacketSize)
            except ConnectionResetError as e:
                logger.error(
                    "obtain_prerocess - recv exception  err={}    trace={}".format(
                        e, traceback.format_exc()
                    )
                )

                return

            if data is None:
                time.sleep(0.5)

                continue

            if data == b"":
                logger.warning("obtain_prerocess - recv EOF-[{}]".format(data))

                break

            buffer = buffer + data
            if 4 > len(buffer):
                logger.warning(
                    "obtain_prerocess - The header length of the read packet is less than 4 bytes, and the actual length is {}.".format(
                        len(buffer)
                    )
                )

                continue

            # Read head from packet
            bs_msg_len = buffer[:HeaderSize]
            bs_len = struct.unpack("i", bs_msg_len)[0]

            if bs_len > len(buffer[HeaderSize:]):
                logger.warning(
                    "obtain_prerocess - The data has not been received yet, the total size is {} bytes, and now only {} bytes are received.".format(
                        bs_len, len(buffer[HeaderSize:])
                    )
                )

                continue

            # Read data from packet
            ppos = bs_len + HeaderSize
            data = buffer[HeaderSize:ppos]
            buffer = buffer[ppos:]

            pqueue.put(pickle.loads(data))
            pass

    def _reply_caller(self, body=None, sid: str = ""):
        pkt = Packet(sid=sid, body=body, size=len(body) if body is not None else 0)
        body = pickle.dumps(pkt)
        msg_len_bs = struct.pack("i", len(body))

        if self.connect is None:
            return

        self.connect.sendall(msg_len_bs + body)
        return

    def main(self):
        if self.func is None:
            return

        while True:
            try:
                pkt: Packet = self.pqueue.get()
                if pkt is None:
                    time.sleep(0.1)

                    continue

                logger.info(
                    "main - Receive new data, packet info sid={} size={}".format(
                        pkt.sid(), pkt.size()
                    )
                )

                # Execute business logic
                body = self.func(args=pkt.body(), ctx=self.ctx)
                self._reply_caller(body=body, sid=pkt.sid())
            except Exception as err:
                logger.error(
                    "main - func called is error occured, err={}    trace={}".format(
                        err, traceback.format_exc()
                    )
                )
                time.sleep(1)

    def run(self):
        logging.basicConfig(
            filename="myapp.log.{}".format(self.pid), level=logging.INFO
        )

        if self.func is None:
            logger.warn(
                "Start Excutor fail, becuase func is None, pid={}".format(self.pid)
            )

            return

        self.wait_connect()
        self.start_service()

        logger.info(
            "Excutor Start main, Can accept processing requests, uri={} pid={}".format(
                self._uri, self.pid
            )
        )
        self.main()
        self.release()
        return
