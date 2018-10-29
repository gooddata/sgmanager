# SPDX-License-Identifier: BSD-3-Clause
# Copyright © 2018, GoodData Corporation. All rights reserved.

import ipaddress
import itertools
import logging

from .exceptions import InvalidConfiguration
from .utils import Base, StrEnum

logger = logging.getLogger(__name__)


class Direction(StrEnum):
    Ingress = 'ingress'
    Egress = 'egress'


class EtherType(StrEnum):
    IPv4 = 'IPv4'
    IPv6 = 'IPv6'


class Protocol(StrEnum):
    TCP = 'tcp'
    UDP = 'udp'
    ICMP = 'icmp'


class Rule(Base):
    '''Single rule.'''
    def __init__(self,
                 direction='ingress',
                 ethertype=None,
                 protocol=None,
                 port_min=None,
                 port_max=None,
                 cidr=None,
                 group=None):
        self.direction = direction
        self.ethertype = ethertype
        self.protocol = protocol
        self.port_min = port_min
        self.port_max = port_max
        self.cidr = cidr
        self.group = group
        self._id = None

    def to_dict(self, user=False):
        '''Convert object to dictionary, mangling options for best user view if requested.'''
        if user:
            d = {}
            if self.protocol is not None:
                d['protocol'] = self.protocol
            if self.direction != Direction.Ingress:
                # This is kinda default
                d['direction'] = self.direction
            if self.ethertype != EtherType.IPv4:
                # This is kinda default
                d['ethertype'] = self.ethertype
            if self.port_min is not None:
                if self.port_min == self.port_max:
                    d['port'] = self.port_min
                else:
                    d['port_min'] = self.port_min
                    d['port_max'] = self.port_max
            if self.cidr is not None:
                d['cidr'] = (self.cidr,)
            if self.group is not None:
                d['groups'] = (self.group,)
            return d
        else:
            return {'direction': self.direction,
                    'ethertype': self.ethertype,
                    'protocol': self.protocol,
                    'port_min': self.port_min,
                    'port_max': self.port_max,
                    'cidr': self.cidr,
                    'group': self.group}

    @classmethod
    def from_remote(cls, **kwargs):
        '''Create rule from OpenStack's json output.'''
        logger.debug(f'Creating remote rule: {kwargs}')
        info = {'direction': kwargs['direction'],
                'ethertype': kwargs['ethertype'],
                'protocol': kwargs['protocol'],
                'port_min': kwargs['port_range_min'],
                'port_max': kwargs['port_range_max'],
                'cidr': kwargs['remote_ip_prefix'],
                'group': kwargs['remote_group_id']}

        rule = cls(**info)
        rule._id = kwargs['id']
        return rule

    @classmethod
    def from_local(cls, **kwargs):
        '''Create rule from local configuration.'''
        logger.debug(f'Creating local rule: {kwargs}')
        kwargs = dict(kwargs)

        # COMPAT
        if 'port_from' in kwargs:
            kwargs['port_min'] = kwargs.pop('port_from')
        if 'port_to' in kwargs:
            kwargs['port_max'] = kwargs.pop('port_to')

        port = kwargs.pop('port', None)
        if port is not None:
            port_min = kwargs.pop('port_min', None)
            port_max = kwargs.pop('port_max', None)
            if port_min is not None or port_max is not None:
                raise InvalidConfiguration(f'Both port and port_min/port_max are specified')
            kwargs['port_min'] = kwargs['port_max'] = port

        return cls(**kwargs)

    @classmethod
    def expand_local(cls, **kwargs):
        '''Expand configuration to multiple rules (or single rule) based on properties.'''
        logger.debug(f'Expanding local rule: {kwargs}')
        kwargs = dict(kwargs)

        exp_to = kwargs.pop('to', [{}])
        overwritten = set(key
                          for to in exp_to
                          for key in kwargs.keys() & to.keys())
        if overwritten:
            # XXX: do we actually want this warning?
            logger.warning(f"Item(s) from 'to' override base option(s): {', '.join(overwritten)}")

        if 'cidr' not in kwargs:
            if 'groups' in kwargs:
                cidr = []
            elif 'ethertype' not in kwargs:
                # XXX: Shouldn't we set ipv6 by default?
                cidr = ['0.0.0.0/0']
            else:
                ethertype = EtherType(kwargs['ethertype'])
                if ethertype == EtherType.IPv4:
                    cidr = ['0.0.0.0/0']
                elif ethertype == EtherType.IPv6:
                    cidr = ['::/0']
                else:
                    raise RuntimeError(f'Unknown type: {type(ethertype)}')
        else:
            cidr = kwargs.pop('cidr')

        expand_data = {'cidr': cidr,
                       'group': kwargs.pop('groups', [])}
        exp_location = [{k: v}
                        for k, values in expand_data.items()
                        for v in values]

        # Expand: to × (cidr + groups)
        return [cls.from_local(**{**kwargs, **p1, **p2})
                for p1, p2 in itertools.product(exp_to, exp_location)]

    @property
    def direction(self):
        return self._direction

    @direction.setter
    def direction(self, value):
        self._direction = Direction(value)

    @property
    def ethertype(self):
        if self._ethertype is None:
            if self.cidr is None:
                # Some sane default
                return EtherType.IPv4
            else:
                for net, typ in ((ipaddress.IPv4Network, EtherType.IPv4),
                                 (ipaddress.IPv6Network, EtherType.IPv6)):
                    if isinstance(self.cidr, net):
                        return typ

            raise RuntimeError(f'Unknown type: {type(self.cidr)}')

        return self._ethertype

    @ethertype.setter
    def ethertype(self, value):
        self._ethertype = EtherType(value) if value is not None else None

    @property
    def protocol(self):
        return self._protocol

    @protocol.setter
    def protocol(self, value):
        self._protocol = Protocol(value) if value is not None else None

    @staticmethod
    def _check_port(port):
        # COMPAT: port == -1
        if port is None or port == -1:
            return None
        if 0 <= port < 65536:
            return port

        raise TypeError(f'Port is out of the range (0; 65535): {port}')

    @property
    def port_min(self):
        return self._port_min

    @port_min.setter
    def port_min(self, value):
        self._port_min = self._check_port(value)

    @property
    def port_max(self):
        return self._port_max

    @port_max.setter
    def port_max(self, value):
        self._port_max = self._check_port(value)

    @property
    def cidr(self):
        return self._cidr

    @cidr.setter
    def cidr(self, value):
        self._cidr = ipaddress.ip_network(value) if value is not None else None

    def validate(self):
        '''Validate rule.'''
        if self.port_min is None and self.port_max is not None:
            raise InvalidConfiguration('port_min is set, but port_max is not')
        elif self.port_max is None and self.port_min is not None:
            raise InvalidConfiguration('port_max is set, but port_min is not')

        if self.protocol == Protocol.ICMP and (self.port_min is not None or
                                               self.port_max is not None):
            raise InvalidConfiguration('Protocol is set to ICMP and port is specified')

        if self.cidr is not None:
            for ethertype, net in ((EtherType.IPv4, ipaddress.IPv4Network),
                                   (EtherType.IPv6, ipaddress.IPv6Network)):
                if self.ethertype == ethertype and not isinstance(self.cidr, net):
                    raise InvalidConfiguration(f'EtherType is set to {ethertype},'
                                               f' but address is {type(self.cidr)}')
