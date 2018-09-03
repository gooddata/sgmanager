# SPDX-License-Identifier: BSD-3-Clause
# Copyright © 2018, GoodData Corporation. All rights reserved.

import logging

from orderedset import OrderedSet

from .rule import Rule
from .utils import Base

logger = logging.getLogger(__name__)


class Group(Base):
    '''Single group with its rules.'''
    def __init__(self, name, description=None, rules=None):
        self.name = name
        self.description = description
        self.rules = OrderedSet(rules)
        self._id = None

    def to_dict(self, user=False):
        '''Convert object to dictionary, mangling options for best user view if requested.'''
        if user:
            d = {}
            if self._description is not None and self.description != self.name:
                d['description'] = self.description
            if len(self.rules) > 0:
                d['rules'] = tuple(self.rules)
            return d
        else:
            return {'name': self.name,
                    'description': self.description,
                    'rules': self.rules}

    @property
    def description(self):
        return self._description or self.name

    @description.setter
    def description(self, value):
        self._description = value

    def __eq__(self, other):
        if not isinstance(other, Group):
            return NotImplemented
        d1 = self.to_dict(True)
        d2 = other.to_dict(True)
        for d in (d1, d2):
            d['rules'] = set(d.pop('rules', []))
        return d1 == d2

    def __hash__(self):
        d = self.to_dict(True)
        d['name'] = self.name
        return hash(frozenset(d.items()))

    @classmethod
    def from_remote(cls, **kwargs):
        '''Create group from OpenStack's json output.'''
        logger.debug(f'Creating remote group: {kwargs}')
        info = {'name': kwargs['name'],
                'description': kwargs.get('description'),
                'rules': [Rule.from_remote(**rule)
                          for rule in kwargs['security_group_rules']]}
        group = cls(**info)
        group._id = kwargs['id']
        return group

    @classmethod
    def from_local(cls, **kwargs):
        '''Create group from local configuration.'''
        logger.debug(f'Creating local group: {kwargs}')
        kwargs = dict(kwargs)

        kwargs['rules'] = [rule
                           for rule in kwargs.pop('rules', [])
                           for rule in Rule.expand_local(**rule)]
        return cls(**kwargs)

    def validate(self):
        '''Validate group and its rules.'''
        for rule in self.rules:
            rule.validate()
