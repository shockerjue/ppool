#!/usr/bin/python
# -*- coding: UTF-8 -*-
#

# Context for process
#
class Context(object):
    # obj  User object, used to pass between processes
    def __init__(self, obj: object = None) -> None:
        super().__init__()
        self.obj = obj

        pass
