#!/usr/bin/python
# -*- coding: UTF-8 -*-

import sys
import time
import threading
import socket
import queue
import traceback
import logging
from typing import Union

sys.path.append(".")
sys.path.append("..")

from ppool.excutor import Excutor
from ppool.caller import Caller
from ppool.common import Packet
from ppool.common import Result
from ppool.object import Object
from ppool.context import Context

logger = logging.getLogger(__name__)


class manage(Object):
    def __init__(
        self,
        excutor: Union[Excutor, None] = None,
        caller: Union[Caller, None] = None,
        create_at: int = 0,
        inuse=False,
    ) -> None:
        super().__init__()
        self._excutor: Union[Excutor, None] = excutor
        self._caller: Union[Caller, None] = caller
        self._inuse: bool = inuse
        self._create_at: int = create_at
        self._failure: int = 0
        self._success: int = 0
        self._puid: str = str(time.time() * 10000)
        self._puid = self._puid.replace(".", "")
        self._name = "manage"

        pass

    def puid(self):
        return self._puid

    def excutor(self):
        return self._excutor

    def caller(self):
        return self._caller

    def inuse(self):
        return self._inuse

    def set_inuse(self, use):
        self._inuse = use
        pass

    def create_at(self):
        return self._create_at

    def set_create_at(self, at):
        self._create_at = at

    def inc_failure(self):
        self._failure += 1

    def dec_failure(self):
        if 0 == self._failure:
            return

        self._failure -= 1

    def inc_success(self):
        self._success += 1

    def success(self):
        return self._success

    def failure(self):
        return self._failure


class Pool(Object):
    """
    Process pool object.
    Paramater:
        size:   The size of the process pool
        func:   The method to be executed by the process pool
        ctxs:   The context of each process, mainly used to carry user data
        default_ctx:   The default context, when ctx

        Among them, ctx and default_ctx are Context objects, which are used to pass user data and serve as parameters of user callbacks.
        Usage: When model reasoning is needed, model objects can be stored in it, mainly to pass process-specific data or objects.
    """

    def __init__(self, amount=1, func=None, ctxs=(), default_ctx=None) -> None:
        super().__init__()
        self.ports = []
        self.lock = threading.Lock()
        self.func = func
        self.amount = amount
        self.queue_idle = queue.Queue(maxsize=amount + 1)  # Available process queues
        self.queue_used = queue.Queue(maxsize=amount + 1)  # Process queue in use
        self._name = "Pool"
        self.ctxs = ctxs
        self.default_ctx = default_ctx

        i = 0
        while i < amount:
            ctx: Union[Context, None] = ctxs[i] if i < len(ctxs) else None

            self._gen_pool_node(ctx=ctx)
            i += 1

        pass

    def release(self, node=None):
        if node is None:
            return

        node.excutor().release()
        node.caller().release()
        node.excutor().terminate()

        logger.warning("Pool release success ---------> ")
        return

    def _gen_pool_node(self, inuse=False, ctx: Union[Context, None] = None):
        try:
            port = Pool.get_free_tcp_port()
            uri = ("127.0.0.1", port)
            mini = Excutor(func=self.func, uri=uri, ctx=ctx)
            mini.start()

            time.sleep(2)
            alter = Caller(uri=uri)

            m = manage(
                excutor=mini,
                caller=alter,
                create_at=int(time.time() * 1000),
                inuse=inuse,
            )
            self.queue_idle.put(m)

            logger.info(
                "_gen_pool_node - gen node is success,  pid={}  puid={}".format(
                    mini.pid, m.puid()
                )
            )
        except Exception as e:
            logger.error(
                "_gen_pool_node - gen node  err={} trace={}".format(
                    e, traceback.format_exc()
                )
            )

    @staticmethod
    def get_free_tcp_port():
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.bind(("", 0))
        _, port = tcp.getsockname()
        tcp.close()

        return port

    def _try_get_idle(self, try_times=1) -> manage:
        if self.amount > (self.queue_idle.qsize() + self.queue_used.qsize()):
            self._gen_pool_node()

        times = 0
        while times < try_times:
            times += 1
            if 0 == self.queue_idle.qsize():
                logger.warning(
                    "_try_get_idle get ndoe fail, sleep 100ms retry ....... {}".format(
                        times
                    )
                )

                # sleep 100ms
                time.sleep(0.1)
                continue

            m = self.queue_idle.get()
            self.queue_used.put(m)

            curAt = time.time()
            past = (curAt * 1000) - m.create_at()
            if 2 < m.failure() or (
                m.inuse() is True and 0 != m.create_at() and 3000 < int(past)
            ):
                logger.warning(
                    "_try_get_idle failure,puid={}  pid={} failure={}   timeout:{}ms".format(
                        m.puid(),
                        m.excutor().pid,
                        m.failure(),
                        past,
                    )
                )

                self.queue_used.get()
                self.release(node=m)
                continue

            if m.inuse() is True:
                self.queue_used.get()

                continue

            logger.info(
                "_try_get_idle success, puid={} pid={}  failure={} success={}".format(
                    m.puid(), m.excutor().pid, m.failure(), m.success()
                )
            )
            m.set_inuse(True)
            m.set_create_at(int(time.time() * 1000))
            return m

        return None

    # Select an idle process from the process pool to execute the business
    # After the acquisition fails, it will try 3 times
    #
    # @param    args   Method parameters executed by the process pool 
    # @param    timeout Execution timeout
    def apply(self, args=None, timeout=1, try_times=1) -> Result:
        _at = time.time()
        if self.func is None:
            return Result(
                value=None,
                pkt=None,
                code=505,
                msg="apply failure, for func call is None",
                cost=int(time.time() * 1000) - int(_at * 1000),
            )

        node = self._try_get_idle(try_times=try_times)
        if node is None:
            logger.warning("_try_get_idle return is None, start use local mode.")

            try:
                value = self.func(args=args, ctx=self.default_ctx)
                return Result(
                    value=value,
                    pkt=Packet(),
                    code=0,
                    msg="Call local method!",
                    cost=int(time.time() * 1000) - int(_at * 1000),
                )
            except Exception as e:
                return Result(
                    value=None,
                    pkt=None,
                    code=401,
                    msg="Do not found handle process! Call local method exception. {}   {}".format(
                        traceback.format_exc(), e
                    ),
                    cost=int(time.time() * 1000) - int(_at * 1000),
                )

        msg = ""
        try:
            pkt = Packet(
                sid=str(time.time()).replace(".", ""),
                body=args,
                size=(len(args) if args is not None else 0),
            )
            resPkt = node.caller().apply(pkt=pkt, timeout=timeout)
            if resPkt is None:
                node.inc_failure()

                return Result(
                    value=None,
                    pkt=resPkt,
                    code=402,
                    msg="apply return is None",
                    cost=int(time.time() * 1000) - int(_at * 1000),
                )

            if pkt.sid() != resPkt.sid():
                node.inc_failure()

                return Result(
                    value=None,
                    pkt=resPkt,
                    code=403,
                    msg="apply sid is error, sid={} puid={}".format(
                        pkt.sid(), node.puid()
                    ),
                    cost=int(time.time() * 1000) - int(_at * 1000),
                )

            node.inc_success()
            logger.info(
                "apply call responsed.used={}   idle={} sid={}  puid={}   success={}   failure={} cost={}ms  ".format(
                    self.queue_used.qsize(),
                    self.queue_idle.qsize(),
                    resPkt.sid(),
                    node.puid(),
                    node.success(),
                    node.failure(),
                    int(time.time() * 1000) - int(_at * 1000),
                )
            )

            return Result(
                value=resPkt.body(),
                pkt=resPkt,
                msg="Success",
                cost=int(time.time() * 1000) - int(_at * 1000),
            )
        except Exception as e:
            logger.error(
                "processes apply is error,used={}   idle={}  puid={}  success={}   failure={}   cost={}ms err={}    trace={}".format(
                    self.queue_used.qsize(),
                    self.queue_idle.qsize(),
                    node.puid(),
                    node.success(),
                    node.failure(),
                    int(time.time() * 1000) - int(_at * 1000),
                    e,
                    traceback.format_exc(),
                )
            )

            node.inc_failure()
            msg = traceback.format_exc()
        finally:
            self.queue_used.get()
            if 2 < node.failure():
                self.release(node=node)
            else:
                node.set_inuse(False)
                node.dec_failure()
                node.inc_success()
                node.set_create_at(0)

                self.queue_idle.put(node)

        return Result(
            value=None,
            pkt=None,
            code=501,
            msg=msg,
            cost=int(time.time() * 1000) - int(_at * 1000),
        )
