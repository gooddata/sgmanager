#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved

import os
import boto
import yaml
from gdc.sgmanager.exceptions import *

# TODO: diff local and remote groups and their rules
# TODO: apply differences

class SGManager(object):
    ec2 = None

    config = None

    remote = None
    local = None

    def __init__(self, **kwargs):
        """
        Connect to EC2
        :param config: path to configuration file
        :param kwargs: parameters for boto.connect_ec2()
        """
        self.ec2 = boto.connect_ec2(**kwargs)

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
    ec2 = None
    groups = None
    config = None

    def __init__(self, ec2):
        """
        Create instance, save ec2 connection
        :param ec2: boto.ec2.EC2Connection
        """
        self.ec2 = ec2
        self.groups = {}

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
                    'port' : int(rule.to_port),
                    'protocol'  : str(rule.ip_protocol),
                    'groups' : None,
                }

                if rule.from_port != rule.to_port:
                    rule_info['port_from'] = int(rule.from_port)

                # For each granted permission
                for grant in rule.grants:
                    try:
                        rule_info['groups'].append({
                                'name'  : grant.groupName,
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
            sgroup = SGroup(name, None if not group.haskey('description') else group['description'])

            for rule in group['rules']:
                # Initialize SRule object
                srule = SRule(**rule)
                # Add it into group
                sgroup.add_rule(srule)

            self.groups[name] = sgroup

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
        # TODO: fixme (broken by refactoring)
        return yaml.dump(self.groups)


class SGroup(object):
    """
    Single security group and it's rules
    """
    def __init__(self, name=None, description=None, rules=[]):
        self.name = name
        self.description = description
        self.rules = rules

        # Set group membership for rules
        for rule in rules:
            rule.group = self

    def add_rule(self, rule):
        """
        Add new rule
        """
        assert isinstance(rule, SRule), "Given rule is not instance of SRule but %s" % type(rule)
        rule.set_group(self)
        self.rules.append(rule)


class SRule(object):
    """
    Single security group rule
    """
    def __init__(self, port=None, port_from=None, port_to=None, groups=[], protocol='tcp', cidr=None):
        """
        Initialize variables
        """
        # TODO: fix name - we want to identify the rules (index?)
        self.name = 'TODO'

        self.protocol = protocol
        self.port = port
        self.port_from = port_from
        self.port_to = port_to

        self.groups = groups
        self.group = None

        # Check validity of groups parameter
        if self.groups:
            if not isinstance(self.groups, list):
                raise InvalidConfiguration('Parameter groups should be list of allowed security groups for rule %s' % self.name)

            # Unify format for granted group permissions
            # it has to contain id and group owner (account id)
            for group in groups:
                if not isinstance(group, dict):
                    group = {
                        'name' : group,
                        'owner': None,
                        'id'   : None,
                    }

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
        if not isinstance(self.port, int):
            raise InvalidConfiguration('Port must be integer for rule %s' % self.name)

        if self.port_from and not isinstance(self.port_from, int):
            raise InvalidConfiguration('Parameter port_from must be integer for rule %s' % self.name)

        if self.port_to and not isinstance(self.port_to, int):
            raise InvalidConfiguration('Parameter port_to must be integer for rule %s' % self.name)

        if self.protocol and self.protocol not in ['tcp', 'udp', 'icmp']:
            raise InvalidConfiguration('Protocol must be tcp, udp or icmp, not %s for rule %s' % (self.protocol, self.name))