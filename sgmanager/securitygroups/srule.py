# -*- coding: utf-8 -*-
# Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved

import logging
from itertools import count

import sgmanager
from sgmanager.exceptions import InvalidConfiguration


# Logging should be initialized by cli
lg = logging.getLogger(__name__)


class SRule(object):
    """
    Single security group rule
    """
    _ids = count(0)

    def __init__(self, owner_id=None, port=None, port_from=None, port_to=None, groups=None, protocol='tcp', cidr=None, srule_object=None):
        """
        Initialize variables
        """
        global ec2
        ec2 = sgmanager.ec2

        # Set rule id
        self._ids = self._ids.next()
        self.object = srule_object

        self.protocol = protocol
        self.port = port
        self.port_from = port_from
        self.port_to = port_to
        self.owner_id = owner_id

        # All ports allowed but only port_to supplied -> complete port range by setting port_from
        if not self.port_from and self.port_to:
            self.port_from = 1

        # Single port can't be supplied together with port range
        if self.port and self.port_from and self.port_to:
            raise InvalidConfiguration('Single port and port range supplied for rule %s' % self._ids)

        self.groups = []
        self.group = None

        # Check validity of groups parameter
        if groups:
            if not isinstance(groups, list):
                # Convert to list so it can be full dict structure or simple group name
                groups = [ groups ]

            # Unify format for granted group permissions
            # it has to contain id and group owner (account id)
            for group in groups:
                if isinstance(group, dict) and len(group) == 1:
                    # There's only one element in dict (suppose it's name),
                    # convert the dict to unify it
                    try:
                        group = group['name']
                    except Exception:
                        raise InvalidConfiguration("Group definition doesn't contain name, rule %s" % self._ids)

                if not isinstance(group, dict):
                    # Empty owner and id, only name supplied, prepare full
                    # structure
                    self.groups.append({
                        'name' : group,
                        'owner': owner_id,
                        'id'   : None,
                    })
                else:
                    # ..otherwise suppose we already have required structure
                    self.groups.append(group)

        # cidr should be None if we have groups
        if groups:
            self.cidr = None
        elif not cidr:
            # No cidr, no groups, allowed from everywhere
            self.cidr = ['0.0.0.0/0']
        else:
            # We have cidr and no groups, unify structure
            # convert string cidr to list
            if cidr and not isinstance(cidr, list):
                self.cidr = [ cidr ]
            else:
                self.cidr = cidr

        self._check_configuration()
        self.name = self._generate_name()

        lg.debug('Loaded rule %s' % self.name)

    def _generate_name(self):
        """
        Generate human-readable name for rule
        """
        params = [
            'proto=%s' % self.protocol,
        ]

        if self.cidr and self.cidr[0] != '0.0.0.0/0':
            # TODO: does EC2 even support granting access to multiple cidrs at once? For now, use single one.
            params.append('cidr=%s' % self.cidr[0])

        if self.port:
            # We have single port
            params.append('port=%s' % self.port)
        elif self.port_from and self.port_to:
            # We have port range
            params.append('port=%s:%s' % (self.port_from, self.port_to))

        if self.groups:
            # Add group parameter
            # TODO: does EC2 even support granting access to multiple groups at once? For now, use single one.
            group = self.groups[0]
            params.append('name=%s' % group['name'])

            # Do we have owner id?
            if group['owner']:
                params.append('owner=%s' % group['owner'])

        return '<%s>' % ','.join(params)

    def set_group(self, group):
        """
        Set group membership
        """
        self.group = group

    def _check_configuration(self):
        """
        Check configuration
        """
        if self.port and not isinstance(self.port, int):
            raise InvalidConfiguration('Port must be integer for rule %s not %s' % (self.name, type(self.port).__name__))

        if self.port_from and not isinstance(self.port_from, int):
            raise InvalidConfiguration('Parameter port_from must be integer for rule %s not %s' % (self.name, type(self.port_from).__name__))

        if self.port_to and not isinstance(self.port_to, int):
            raise InvalidConfiguration('Parameter port_to must be integer for rule %s not %s' % (self.name, type(self.port_to).__name__))

        if self.protocol and self.protocol not in ['tcp', 'udp', 'icmp']:
            raise InvalidConfiguration('Protocol must be tcp, udp or icmp, not %s for rule %s' % (self.protocol, self.name))

    def dump(self):
        """
        Return dictionary structure
        Don't return empty values
        """
        result = {}

        for attr in ['protocol', 'port', 'port_to', 'port_from', 'cidr', 'groups']:
            if getattr(self, attr):
                if attr == 'cidr' and getattr(self, attr)[0] == '0.0.0.0/0':
                    # Skip global cidr which is the default
                    continue
                elif attr == 'groups' and getattr(self, attr):
                    # Remove unwanted data from groups (if any)
                    result[attr] = []

                    for group in getattr(self, attr):
                        if isinstance(group, dict):
                            if group.has_key('owner') and group['owner'] == self.owner_id:
                                # Leave only name, no need to define owner
                                result[attr].append(group['name'])
                            else:
#                                if group.has_key('id') and not group['id']:
#                                    # Id is empty, pop it out
#                                    group.pop('id')
                                result[attr].append(group)
                        else:
                            result[attr].append(group)
                else:
                    result[attr] = getattr(self, attr)


        return result

    def __ne__(self, other):
        """
        Not equal matching, call __eq__ but reverse output
        """
        return not self.__eq__(other)

    def __eq__(self, other):
        """
        Compare SRule objects
        """
        if not isinstance(other, SRule):
            raise TypeError("Compared object must be instance of SRule, not %s" % type(other).__name__)

        # Match common attributes
        for attr in ['protocol', 'port', 'port_to', 'port_from', 'cidr']:
            if getattr(self, attr) != getattr(other, attr):
                return False

        # Match groups (names and owner only)
        for group in self.groups:
            for group_other in other.groups:
                if group['name'] != group_other['name']:
                    return False
                if group['owner'] != group_other['owner']:
                    return False

        return True

    def __repr__(self):
        return '<SRule %s of group %s>' % (self.name, self.group.name)

    def add_rule(self, dry=False):
        """
        Add rule into security group
        """
        lg.info('Adding rule %s into group %s' % (self.name, self.group.name))

        if not dry:
            ec2.authorize_security_group(**self._get_boto_params())

    def remove_rule(self, dry=False):
        """
        Revoke rule
        """
        lg.info('Removing rule %s from group %s' % (self.name, self.group.name))
        if not dry:
            ec2.revoke_security_group(**self._get_boto_params())

    def _get_boto_params(self):
        """
        Get parameters for boto
        """
        params = {
            'group_name' : self.group.name,
            'ip_protocol':  self.protocol,
        }

        if self.cidr:
            # TODO: does EC2 even support granting access to multiple cidrs at once? For now, use single one.
            params['cidr_ip'] = self.cidr[0]

        if self.port:
            # We have single port
            params['to_port'] = self.port
            params['from_port'] = self.port
        elif self.port_from and self.port_to:
            # We have port range
            params['from_port'] = self.port_from
            params['to_port'] = self.port_to

        if self.groups:
            # Add group parameter
            # TODO: does EC2 even support granting access to multiple groups at once? For now, use single one.
            group = self.groups[0]
            params['src_security_group_name'] = group['name']

            # Do we have owner id?
            if group['owner']:
                params['src_security_group_owner_id'] = group['owner']

        return params
