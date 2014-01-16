# -*- coding: utf-8 -*-
# Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved

import logging

import boto.ec2
from sgmanager.securitygroups import SecurityGroups

from sgmanager.exceptions import InvalidConfiguration

global ec2

# Logging should be initialized by cli
lg = logging.getLogger(__name__)


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