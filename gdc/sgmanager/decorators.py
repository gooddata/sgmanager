# -*- coding: utf-8 -*-
# Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved


class CachedMethod(object):
    """
    Decorator for caching of function results
    """
    def __init__ (self, function):
        self.function = function
        self.mem = {}

    def __call__ (self, *args, **kwargs):
        if kwargs.has_key('cached') and kwargs['cached'] == True:
            if (args, str(kwargs)) in self.mem:
                return self.mem[args, str(kwargs)]

        tmp = self.function(*args, **kwargs)
        self.mem[args, str(kwargs)] = tmp
        return tmp

    def __get__(self, obj, objtype):
        """ Support instance methods """
        import functools
        return functools.partial(self.__call__, obj)