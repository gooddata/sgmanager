# -*- coding: utf-8 -*-
# Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved

import logging
import sgmanager
from sgmanager.decorators import CachedMethod
from sgmanager.securitygroups.srule import SRule
from copy import deepcopy

# Logging should be initialized by cli
lg = logging.getLogger(__name__)


class SGroup(object):
    """
    Single security group and it's rules
    """
    def __init__(self, name=None, description=None, rules=None, sgroup_object=None, vpc_id=None):
        """
        Initialize variables
        """
        global ec2
        ec2 = sgmanager.ec2

        if sgroup_object:
            # load basic informations from object
            self.name = str(sgroup_object.name)
            self.description = str(sgroup_object.description)
            self.vpc_id = sgroup_object.vpc_id
            self.object = sgroup_object
        else:
            self.name = name
            self.description = description
            self.vpc_id = vpc_id

        if not rules:
            self.rules = []
        else:
            # Set group membership for rules
            for rule in rules:
                rule.set_group(self)
                self.rules.append(rule)

        lg.debug("Initialized group %s" % self.name)

    def add_rule(self, rule):
        """
        Add new rule
        """
        assert isinstance(rule, SRule), "Given rule is not instance of SRule but %s" % type(rule)
        rule.set_group(self)
        self.rules.append(rule)

    def dump(self, merge_by=['to', 'from']):

        def merge(rules, what='to'):
            """
            Merge rules before dumping
            """
            def format_key(rule, by):
                if 'to' in rule and isinstance(rule['to'], list):
                    rule['to'].sort()
                # supposing str orders dict to be always the same
                return str(dict((k, v) for (k, v) in rule.items() if k in by))

            def merge_rules(r1, r2):
                for key in combine:
                    if key in r2 and key not in r1:
                        r1[key] = r2[key]
                    elif key in r2 and key in r1:
                        r1[key].extend(r2[key])

                if pack:
                    if pack_key in r1:
                        r1[pack_key].append(
                            dict((k, r2.get(k)) for k in pack if r2.get(k)))
                    else:
                        r1[pack_key] = [
                            dict((k, r1.get(k)) for k in pack if r1.get(k)),
                            dict((k, r2.get(k)) for k in pack if r2.get(k))]
                    # remove port, proto, etc but not "to":
                    for k in pack:
                        if k != pack_key:
                            r1.pop(k, None)

            if what == 'to':
                by = ['groups', 'cidr']
                combine = []
                pack = ['protocol', 'port', 'port_from', 'port_to', 'to']
            else:  # 'from'
                by = ['protocol', 'port', 'port_from', 'port_to',  'to']
                combine = ['groups', 'cidr']
                pack = []

            pack_key = 'to'
            seen = {}
            new_rules = []
            new_rule_idx = 0

            for rule in rules:
                if format_key(rule, by) not in seen:
                    new_rules.append(deepcopy(rule))
                    seen[format_key(rule, by)] = new_rule_idx
                    new_rule_idx += 1
                else:
                    idx = seen[format_key(rule, by)]
                    # this awesome check only filter out rules like: upd 123 from 0.0.0.0/0
                    # which tend to be mask easily by merging with some other rules
                    if len([k for k in new_rules[idx].keys() if k not in by]) != 0 and len([k for k in rule.keys() if k not in by]):
                        merge_rules(new_rules[idx], rule)
                    else:
                        new_rules.append(deepcopy(rule))

            return new_rules

        """
        Return dictionary structure
        """

        rules = [rule.dump() for rule in self.rules]

        for how in merge_by:
            rules = merge(rules, how)

        dump = {
            'description': self.description,
            'rules': rules,
        }

        if self.vpc_id:
            dump['vpc_id'] = self.vpc_id

        return dump

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
    def compare(self, other):
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
                    lg.debug('Rule %s matched remote rule %s' % (rule.name, rule_other.name))
                    unchanged.append(rule)
                    found = True
                    break
            # Rule not found - need to be added
            if not found:
                lg.debug("Rule %s haven't matched and should be added" % rule.name)
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
            ec2.create_security_group(self.name, self.description, vpc_id=self.vpc_id)

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
