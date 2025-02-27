#!/usr/bin/python
# -*- coding: UTF-8 -*-
#


class Object(object):
    def __init__(self) -> None:
        self._name = "Object"
        self._uri = ""
        pass

    def uri(self):
        return self._uri

    def name(self):
        return self._name
