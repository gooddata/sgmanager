# -*- coding: utf-8 -*-
# Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved

import logging
import sgmanager
from sgmanager.decorators import CachedMethod
from sgmanager.securitygroups.srule import SRule

# Logging should be initialized by cli
lg = logging.getLogger(__name__)


class SGroup(object):
    """
    Single security group and it's rules
    """
    def __init__(self, name=None, description=None, rules=None, sgroup_object=None):
        """
        Initialize variables
        """
        global ec2
        ec2 = sgmanager.ec2

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

        lg.debug("Initialized group %s" % self.name)

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