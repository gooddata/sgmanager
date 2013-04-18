#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved

import os
import boto
import yaml

# TODO: diff local and remote groups and their rules
# TODO: apply differences
# TODO: logging and user-friendly exceptions

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
            self.groups[str(group.name)] = {
                'description' : str(group.description),
                'rules' : []
            }

            # For each rule in group
            for rule in group.rules:
                rule_info = {
                    'port' : int(rule.to_port),
                    'protocol'  : str(rule.ip_protocol)
                }

                if rule.from_port != rule.to_port:
                    rule_info['port_from'] = int(rule.from_port)

                # For each granted permission
                for grant in rule.grants:
                    try:
                        # Rule is granted for another security group
                        if not rule_info.has_key('groups'):
                            rule_info['groups'] = []

                        rule_info['groups'].append({
                            str(grant.groupName) : {
                                'owner' : str(grant.owner_id),
                                'id'    : str(grant.groupId)
                            }
                        })
                    except AttributeError:
                        rule_info['cidr'] = []
                        rule_info['cidr'].append(str(grant.cidr_ip))

                self.groups[group.name]['rules'].append(rule_info)

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
            # TODO: lg.error("Can't read config file %s: %s" % (config, e))
            raise
        except Exception as e:
            # TODO: lg.error("Can't parse config file %s: %s" % (config, e))
            raise

        for name, group in conf.iteritems():
            for rule in group['rules']:
                # Check configuration
                assert isinstance(rule['port'], int), 'Port must be integer for rule %s' % name
                if rule.has_key('port_from'):
                    assert isinstance(rule['port_from'], int),\
                        'Parameter port_from must be integer for rule %s' % name

                if rule.has_key('protocol'):
                    assert (rule['protocol'] in ['tcp', 'udp', 'icmp']),\
                        'Protocol must be tcp, udp or icmp, not %s for rule %s' % (rule['protocol'], name)
                else:
                    rule['protocol'] = 'tcp'
    
                # Unify values..
                # convert string cidr to list
                if rule.has_key('cidr') and not isinstance(rule['cidr'], list):
                    rule['cidr'] = [ rule['cidr'] ]
    
                if rule.has_key('rules'):
                    # Check rule validity
                    assert isinstance(rule['rules'], list),\
                        'Parameter rules should be list of allowed security rules for rule %s' % name
                    for sg in rule['rules']:
                        # Convert rule name to unified dictionary
                        if not isinstance(sg, dict):
                            sg = {
                                sg: { 'id': None, 'owner': None }
                            }
    
                # Default values..
                # allow all if we haven't chosen groups or cidr
                if not rule.has_key('cidr') and not rule.has_key('groups'):
                    rule['cidr'] = ['0.0.0.0/0']

            self.groups[name] = group

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
            # TODO: lg.error("Can't include config file %s: %s" % (filepath, e))
            raise

    def dump_groups(self):
        """
        Return YAML dump of loaded groups
        :rtype : basestring
        """
        return yaml.dump(self.groups)