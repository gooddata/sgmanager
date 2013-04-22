# -*- coding: utf-8 -*-
# Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved

import os
import boto.ec2
import yaml
from gdc.sgmanager.exceptions import InvalidConfiguration
from itertools import count
import logging

global ec2

# Logging should be initialized by cli
lg = logging.getLogger('gdc.sgmanager')


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


class SGManager(object):
    def __init__(self, ec2_connection=None):
        """
        Connect to EC2
        :param config: path to configuration file
        :param kwargs: parameters for boto.connect_ec2()
        """
        global ec2

        if not ec2_connection:
            # Use supplied connection
            try:
                ec2 = boto.connect_ec2()
            except boto.exception.NoAuthHandlerFound as e:
                e.friendly = True
                raise
        else:
            # Try to connect on our own
            ec2 = ec2_connection

        self.remote = None
        self.local  = None
        self.config = None

    def load_remote_groups(self):
        """
        Load security groups and their rules from EC2
        Save and return SecurityGroups object

        :rtype : object
        """
        self.remote = SecurityGroups()
        self.remote.load_remote_groups()
        return self.remote

    def load_local_groups(self, config):
        """
        Load local groups from config file
        Save and return SecurityGroups object

        :param config: configuration file path
        :rtype : object
        """
        self.local = SecurityGroups()
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

    def apply_diff(self, remove_groups=True, remove_rules=True, dry=False):
        """
        Apply diff between local and remote groups
        """
        # Diff groups
        sg_added, sg_removed, sg_updated, sg_unchanged = self.local.compare(self.remote)

        # Create new groups
        # Firstly create all groups, then add all rules (to satisfy between group relations)
        for group in sg_added:
            group.create_group(dry, no_rules=True)

        for group in sg_added:
            for rule in group.rules:
                rule.add_rule(dry)

        # Update groups (create / remove rules)
        for group in sg_updated:
            added, removed, unchanged = group.compare(self.remote.groups[group.name])

            # Add new rules
            for rule in added:
                rule.add_rule(dry)

            # Remove old rules
            if remove_rules is True:
                for rule in removed:
                    rule.remove_rule(dry)

        # Delete groups
        # This should be done at last to avoid between group relations
        if remove_groups is True:
            for group in sg_removed:
                group.remove_group(dry)

class SecurityGroups(object):
    def __init__(self):
        """
        Create instance, save ec2 connection
        """
        self.groups = {}
        self.config = None

    def load_remote_groups(self):
        """
        Load security groups from EC2
        Convert boto.ec2.securitygroup objects into unified structure
        :rtype : list
        """
        groups = ec2.get_all_security_groups()
        for group in groups:
            # Initialize SGroup object
            sgroup = SGroup(str(group.name), str(group.description), sgroup_object=group)

            # For each rule in group
            for rule in group.rules:
                rule_info = {
                    'protocol'  : str(rule.ip_protocol),
                    'groups' : [],
                    'srule_object' : rule,
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
            # Error while loading file
            raise InvalidConfiguration("Can't read config file %s: %s" % (config, e))
        except yaml.YAMLError as e:
            # Error while parsing YAML
            if hasattr(e, 'problem_mark'):
                mark = e.problem_mark
                raise InvalidConfiguration("Can't parse config file %s: error at line %s, column %s" % (config, mark.line+1, mark.column+1))
            else:
                raise InvalidConfiguration("Can't parse config file %s: %s" % (config, e))

        for name, group in conf.iteritems():
            # Initialize SGroup object
            sgroup = SGroup(name, None if not group.has_key('description') else group['description'])

            if group.has_key('rules'):
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

    def has_group(self, name):
        if self.groups.has_key(name):
            return True
        else:
            return False

    def __eq__(self, other):
        """
        Equal matching, just call self.compare and return boolean
        """
        added, removed, updated, unchanged = self.compare(other)
        if added or removed or updated:
            return False
        else:
            return True

    def __ne__(self, other):
        """
        Not equal matching, call __eq__ but reverse output
        """
        return not self.__eq__(other)

    @CachedMethod
    def compare(self, other, cached=False):
        """
        Compare SecurityGroups objects

        Return tuple of lists with SGroups objects (added, removed, updated, unchanged)
        """
        if not isinstance(other, SecurityGroups):
            raise TypeError("Compared object must be instance of SecurityGroups, not %s" % type(other).__name__)

        added = []
        removed = []
        updated = []
        unchanged = []

        for name, group in self.groups.iteritems():
            # Group doesn't exist in target SecurityGroups object
            if not other.has_group(name):
                added.append(group)
                continue

            # Compare matched group
            if group != other.groups[name]:
                # Differs - update
                updated.append(group)
            else:
                # Group is same as other one - unchanged
                unchanged.append(group)

        # Check if some groups shouldn't be removed
        for name, group in other.groups.iteritems():
            if not self.has_group(name):
                removed.append(group)

        return added, removed, updated, unchanged


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
    def __init__(self, name=None, description=None, rules=None, sgroup_object=None):
        self.name = name
        self.description = description
        self.object = sgroup_object

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

    def __eq__(self, other):
        """
        Equal matching, just call self.compare and return boolean
        """
        result = self.compare(other)
        if result is False:
            return False

        added, removed, unchanged = result

        if added or removed:
            return False
        else:
            return True

    def __ne__(self, other):
        """
        Not equal matching, call __eq__ but reverse output
        """
        return not self.__eq__(other)

    @CachedMethod
    def compare(self, other, cached=False):
        """
        Compare SGroup objects

        Return tuple of lists with SGroups objects (added, removed, unchanged).
        If name of groups doesn't match, return False
        """
        if not isinstance(other, SGroup):
            raise TypeError("Compared object must be instance of SecurityGroups, not %s" % type(other).__name__)

        if self.name != other.name:
            return False

        added = []
        removed = []
        unchanged = []

        # Compare our rules with other ones and find which needs to be added
        for rule in self.rules:
            found = False
            for rule_other in other.rules:
                if rule == rule_other:
                    # Found matching rule - unchanged
                    unchanged.append(rule)
                    found = True
                    break
            # Rule not found - need to be added
            if not found:
                added.append(rule)

        # Compare other rules with our ones and find which needs to be removed
        for rule_other in other.rules:
            found = False
            for rule in self.rules:
                if rule_other == rule:
                    found = True
                    break
            # Rule not found - need to be removed from target group
            if not found:
                removed.append(rule_other)

        return added, removed, unchanged

    def __repr__(self):
        return '<SGroup %s>' % self.name

    def create_group(self, dry=False, no_rules=False):
        """
        Create security group and all rules
        """
        lg.info('Adding group %s' % self.name)
        if not dry:
            ec2.create_security_group(self.name, self.description)

        # Add rules
        if not no_rules:
            for rule in self.rules:
                rule.add_rule(dry)

    def remove_group(self, dry=False):
        """
        Remove security group
        """
        # Remove rules
        for rule in self.rules:
            if not dry:
                rule.remove_rule()

        lg.info('Removing group %s' % self.name)
        if not dry:
            self.object.delete()


class SRule(object):
    """
    Single security group rule
    """
    _ids = count(0)

    def __init__(self, port=None, port_from=None, port_to=None, groups=None, protocol='tcp', cidr=None, srule_object=None):
        """
        Initialize variables
        """
        # Set rule id
        self._ids = self._ids.next()
        self.object = srule_object

        self.protocol = protocol
        self.port = port
        self.port_from = port_from
        self.port_to = port_to

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
                raise InvalidConfiguration('Parameter groups should be list of allowed security groups for rule %s' % self._ids)

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
        self.name = self._generate_name()

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

        for attr in ['protocol', 'port', 'port_to', 'port_from', 'groups']:
            if getattr(self, attr):
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

        match = True

        # Match common attributes
        for attr in ['protocol', 'port', 'port_to', 'port_from']:
            if getattr(self, attr) != getattr(other, attr):
                match = False
                break

        # Match groups (names only)
        group_names = [ group['name'] for group in self.groups ].sort()
        group_names_other = [ group['name'] for group in other.groups ].sort()

        if group_names != group_names_other:
            match = False

        return match

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