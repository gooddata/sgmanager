#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved

import os
import boto
import yaml
from gdc.sgmanager.exceptions import *
from itertools import count

# TODO: diff local and remote groups and their rules
# TODO: apply differences

class SGManager(object):
    def __init__(self, **kwargs):
        """
        Connect to EC2
        :param config: path to configuration file
        :param kwargs: parameters for boto.connect_ec2()
        """
        self.ec2 = boto.connect_ec2(**kwargs)

        self.remote = None
        self.local  = None
        self.config = None

    def load_remote_groups(self):
        """
        Load security groups and their rules from EC2
        Save and return SecurityGroups object

        :rtype : object
        """
        self.remote = SecurityGroups(self.ec2)
        self.remote.load_remote_groups()
        return self.remote

    def load_local_groups(self, config):
        """
        Load local groups from config file
        Save and return SecurityGroups object

        :param config: configuration file path
        :rtype : object
        """
        self.local = SecurityGroups(self.ec2)
        self.local.load_local_groups(config)
        return self.local

    def dump_remote_groups(self):
        """
        Dump remote groups into YAML
        """
        return self.remote.dump_groups()

    def dump_local_groups(self):
        """
        Dump local groups into YAML
        """
        return self.local.dump_groups()

class SecurityGroups(object):
    def __init__(self, ec2):
        """
        Create instance, save ec2 connection
        :param ec2: boto.ec2.EC2Connection
        """
        self.ec2 = ec2
        self.groups = {}
        self.config = None

    def load_remote_groups(self):
        """
        Load security groups from EC2
        Convert boto.ec2.securitygroup objects into unified structure
        :rtype : list
        """
        groups = self.ec2.get_all_security_groups()
        for group in groups:
            # Initialize SGroup object
            sgroup = SGroup(str(group.name), str(group.description))

            # For each rule in group
            for rule in group.rules:
                rule_info = {
                    'protocol'  : str(rule.ip_protocol),
                    'groups' : [],
                }

                if rule.from_port != rule.to_port:
                    # We have port range, use port_from and port_to parameters
                    rule_info['port_from'] = int(rule.from_port)
                    rule_info['port_to'] = int(rule.to_port)
                else:
                    # We have single port, use port parameter
                    rule_info['port'] = int(rule.to_port)

                # For each granted permission
                for grant in rule.grants:
                    try:
                        rule_info['groups'].append({
                                'name'  : str(grant.groupName),
                                'owner' : str(grant.owner_id),
                                'id'    : str(grant.groupId)
                            })
                    except AttributeError:
                        rule_info['cidr'] = [ str(grant.cidr_ip) ]

                srule = SRule(**rule_info)
                sgroup.add_rule(srule)

            self.groups[sgroup.name] = sgroup

        return self.groups

    def load_local_groups(self, config):
        """
        Load local groups from config file
        Save and return SecurityGroups object

        :param config:
        :rtype : object
        """
        self.config = config
        yaml.add_constructor('!include', self._yaml_include)

        try:
            with open(config, 'r') as fp:
                conf = yaml.load(fp)
        except IOError as e:
            raise InvalidConfiguration("Can't read config file %s: %s" % (config, e))
        except Exception as e:
            raise InvalidConfiguration("Can't parse config file %s: %s" % (config, e))

        for name, group in conf.iteritems():
            # Initialize SGroup object
            sgroup = SGroup(name, None if not group.has_key('description') else group['description'])

            for rule in group['rules']:
                # Initialize SRule object
                srule = SRule(**rule)
                # Add it into group
                sgroup.add_rule(srule)

            self.groups[name] = sgroup

        return self.groups

    def _yaml_include(self, loader, node):
        """
        Include another yaml file from main file
        This is usually done by registering !include tag
        """
        filepath = "%s/%s" % (os.path.dirname(self.config), node.value)
        try:
            with open(filepath, 'r') as inputfile:
                return yaml.load(inputfile)
        except IOError as e:
            raise InvalidConfiguration("Can't include config file %s: %s" % (filepath, e))

    def dump_groups(self):
        """
        Return YAML dump of loaded groups
        :rtype : basestring
        """
        return yaml.dump({ name : group.dump() for name, group in self.groups.iteritems() }, Dumper=YamlDumper)


class YamlDumper(yaml.SafeDumper):
    """
    Custom YAML dumper that will ignore aliases
    """
    def ignore_aliases(self, _data):
        return True


class SGroup(object):
    """
    Single security group and it's rules
    """
    def __init__(self, name=None, description=None, rules=None):
        self.name = name
        self.description = description

        if not rules:
            self.rules = []
        else:
            # Set group membership for rules
            for rule in rules:
                rule.set_group(self)
                self.rules.append(rule)

    def add_rule(self, rule):
        """
        Add new rule
        """
        assert isinstance(rule, SRule), "Given rule is not instance of SRule but %s" % type(rule)
        rule.set_group(self)
        self.rules.append(rule)

    def dump(self):
        """
        Return dictionary structure
        """
        return {
            'description' : self.description,
            'rules'  : [ rule.dump() for rule in self.rules ],
        }


class SRule(object):
    """
    Single security group rule
    """
    _ids = count(0)

    def __init__(self, port=None, port_from=None, port_to=None, groups=None, protocol='tcp', cidr=None):
        """
        Initialize variables
        """
        # Set rule id
        self._ids = self._ids.next()
        self.name = self._ids

        self.protocol = protocol
        self.port = port
        self.port_from = port_from
        self.port_to = port_to

        self.groups = []
        self.group = None

        # Check validity of groups parameter
        if groups:
            if not isinstance(groups, list):
                raise InvalidConfiguration('Parameter groups should be list of allowed security groups for rule %s' % self.name)

            # Unify format for granted group permissions
            # it has to contain id and group owner (account id)
            for group in groups:
                if not isinstance(group, dict):
                    # Empty owner and id, only name supplied
                    self.groups.append({
                        'name' : group,
                        'owner': None,
                        'id'   : None,
                    })
                else:
                    self.groups.append(group)

        # Allow all if we haven't chosen groups or cidr
        if not cidr and not groups:
            self.cidr = ['0.0.0.0/0']
        else:
            # convert string cidr to list
            if cidr and not isinstance(cidr, list):
                self.cidr = [ self.cidr ]
            else:
                self.cidr = cidr

        self._check_configuration()

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

        for attr in ['protocol', 'port', 'port_to', 'port_from', 'groups']:
            if getattr(self, attr):
                result[attr] = getattr(self, attr)

        return result