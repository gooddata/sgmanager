# SPDX-License-Identifier: BSD-3-Clause
# Copyright © 2018, GoodData Corporation. All rights reserved.

from abc import ABCMeta, abstractmethod
from collections import OrderedDict
from enum import Enum
import itertools

from .yaml import dump


class StrEnum(str, Enum):
    '''Enum whose values are strings.'''
    def __new__(cls, *args):
        for arg in args:
            if not isinstance(arg, str):
                raise TypeError(f'Not text: {arg}')

        return super().__new__(cls, *args)


class Base(metaclass=ABCMeta):
    '''Base class for groups and rules.'''
    @abstractmethod
    def to_dict(self, user=False):
        pass

    @abstractmethod
    def validate():
        pass

    def dump(self):
        return dump(self.to_dict(True))

    def __repr__(self):
        s = ', '.join(f'{k}={v}' for k, v in self.to_dict().items())
        return f'<{self.__class__.__name__}: {s}>'

    def __hash__(self):
        return hash(frozenset(self.to_dict(True).items()))

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.to_dict(True) == other.to_dict(True)

    def __copy__(self):
        return self.from_local(**self.to_dict(True))


def validate_groups(groups):
    '''Validate groups. Including references to other groups from rules.'''
    for group in groups:
        group.validate()

    lkeys = set(group.name for group in groups)

    # Pre-resolve
    for rule in itertools.chain.from_iterable(group.rules for group in groups):
        group = rule.group
        if group is not None and group not in lkeys:
            raise ReferenceError(f'Group {group!r} is referenced but not created')


def dump_groups(groups, **kwargs):
    '''Dump groups to YAML.'''
    # It's much better to see document and version on the top ;)
    data = [{group.name: group}
            for group in sorted(groups, key=lambda g: g.name)]
    return dump(
        OrderedDict(
            {'document': 'sgmanager-groups',
             'version': 1,
             'data': data}),
        **kwargs)
