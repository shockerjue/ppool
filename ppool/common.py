#!/usr/bin/python
# -*- coding: UTF-8 -*-
from typing import Union

HeaderSize = 4
PacketSize = 1024 * 1024 * 16  # 16M


class Packet(object):
    def __init__(self, sid: str = "", body=None, size=None) -> None:
        self._sid = sid
        self._body = body
        self._size = size

        pass

    def sid(self):
        return self._sid

    def body(self):
        return self._body

    def size(self):
        return self._size


class Result(object):
    def __init__(
        self, value=None, pkt: Union[Packet, None] = None, code=0, msg="", cost=0
    ) -> None:
        self._value = value
        self._pkt: Union[Packet, None] = pkt
        self._code: int = code
        self._msg: str = msg
        self._cost = cost

        pass

    def msg(self):
        return self._msg

    def code(self):
        return self._code

    def value(self):
        return self._value

    def packet(self):
        return self._pkt

    def cost(self):
        return self._cost
