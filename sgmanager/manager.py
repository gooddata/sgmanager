# SPDX-License-Identifier: BSD-3-Clause
# Copyright © 2018, GoodData Corporation. All rights reserved.

import logging

from orderedset import OrderedSet

from .exceptions import InvalidConfiguration, ThresholdException
from .group import Group
from .rule import Rule
from .utils import validate_groups
from .yaml import load

logger = logging.getLogger(__name__)


class SGManager:
    '''The Manager.'''
    def __init__(self, connection=None):
        self.connection = connection
        self._local = None
        self._remote = None

    @property
    def connection(self):
        if self._connection is None:
            raise AttributeError('Connection is not set')
        return self._connection

    @connection.setter
    def connection(self, value):
        self._connection = value

    @property
    def local(self):
        if self._local is None:
            raise AttributeError('Local groups are not loaded')
        return self._local

    @local.setter
    def local(self, groups):
        self._local = OrderedSet(groups)

    @property
    def remote(self):
        if self._remote is None:
            raise AttributeError('Remote groups are not loaded')
        return self._remote

    @remote.setter
    def remote(self, groups):
        self._remote = OrderedSet(groups)

    def load_remote_groups(self):
        '''Load groups from OpenStack.'''
        conf = self.connection.list_security_groups()

        self.remote = [Group.from_remote(**info)
                       for info in conf]
        return self.remote

    def load_local_groups(self, config):
        '''Load groups from local configuration file.'''
        with open(config, 'r') as f:
            conf = load(f)

        groups = []
        if not isinstance(conf, dict):
            raise InvalidConfiguration(
                f'The topmost collection must be a mapping,'
                f' not a {type(conf)}')

        def pop_with_type(kwargs, key, typ):
            prefix = f'Key {key!r}'
            if key not in kwargs:
                raise InvalidConfiguration(f'{prefix} must be preset')
            value = kwargs.pop(key)
            if not isinstance(value, typ):
                raise InvalidConfiguration(f'{prefix} must have type {typ},'
                                           f' not a {type(value)}')
            return value

        if isinstance(conf, dict) and 'document' not in conf:
            # COMPAT
            def dict_update(dict1, dict2, overwrite=False, skip_none=False):
                dict1 = dict(dict1)
                dict2 = dict(dict2)

                for key, value in dict2.items():
                    if value is None and skip_none:
                        continue
                    if isinstance(value, dict) and key in dict1:
                        dict1[key] = dict_update(dict1[key], value, overwrite)
                    else:
                        if key in dict1 and not overwrite:
                            continue
                        else:
                            dict1[key] = value

                return dict1

            def fix_include(cfg):
                for key, value in list(cfg.items()):
                    if key == 'include':
                        for include in value:
                            if isinstance(include, dict):
                                include = fix_include(include)
                            cfg = dict_update(cfg, include)
                        cfg.pop('include')
                        continue

                    if isinstance(value, dict):
                        cfg[key] = fix_include(value)

                return cfg

            conf = {'document': 'sgmanager-groups',
                    'version': 1,
                    'data': [{k: v} for k, v in fix_include(conf).items()]}

        document = pop_with_type(conf, 'document', str)
        if document != 'sgmanager-groups':
            raise InvalidConfiguration(f'Document type {document!r} must be "sgmanager-groups"')
        version = pop_with_type(conf, 'version', int)
        if version != 1:
            raise InvalidConfiguration(f'Document version {version!r} is not supported')
        data = pop_with_type(conf, 'data', list)

        if conf:
            raise InvalidConfiguration(f'Extra keys: {", ".join(conf.keys())}')

        for item in data:
            name, info = next(iter(item.items()))
            if len(item.items()) > 1:
                raise InvalidConfiguration(
                    f'Syntax error, for item named {name!r}. Missing indent?')

            groups.append(Group.from_local(**{'name': name, **info}))

        self.local = groups
        return self.local

    def update_remote_groups(self, dry_run=True, threshold=None, remove=True):
        '''Update remote configuration with the local one.'''
        # Copy those so that we can modify them even with dry-run
        local = OrderedSet(self.local)
        remote = OrderedSet(self.remote)

        validate_groups(local)

        def parse_groups(groups):
            groups = {group.name: group for group in groups}
            keys = OrderedSet(groups.keys())
            return groups, keys

        lgroups, lkeys = parse_groups(local)
        rgroups, rkeys = parse_groups(remote)

        changes = 0
        unchanged = 0
        groups_added = OrderedSet()
        groups_updated = OrderedSet()
        groups_removed = OrderedSet()
        rules_added = OrderedSet()
        rules_removed = OrderedSet()

        # Added groups
        for group in (lgroups[name] for name in lkeys - rkeys):
            grp = Group(group.name, group.description)
            groups_added.add(grp)
            rgroups[group.name] = grp
            rkeys.add(grp.name)
            changes += 1

        # Changed groups
        for rgroup, lgroup in ((rgroups[name], lgroups[name])
                               for name in rkeys & lkeys):
            if rgroup not in groups_added:
                unchanged += 1

            if rgroup.description != lgroup.description:
                # XXX: https://review.openstack.org/596609
                # groups_updated.add((rgroup, lgroup))
                pass

            if rgroup.rules != lgroup.rules:
                # Added rules
                for rule in lgroup.rules - rgroup.rules:
                    rules_added.add((rgroup.name, rule))
                    changes += 1

                # Removed rules
                for rule in rgroup.rules - lgroup.rules:
                    if remove:
                        rules_removed.add((rgroup.name, rule))
                        changes += 1
                    else:
                        unchanged += 1
            unchanged += len(rgroup.rules & lgroup.rules)

        # Removed groups
        for group in (rgroups[name] for name in rkeys - lkeys):
            if remove:
                groups_removed.add(group)
                changes += len(group.rules) + 1
            else:
                unchanged += len(group.rules) + 1

        if changes == 0 and not groups_updated:
            return

        # Report result
        logger.info(f'{changes:d} changes to be made:')
        for group in groups_added:
            logger.info(f'  - Create group {group.name!r}')
        for rgroup, lgroup in groups_updated:
            logger.info(f'  - Update description for {rgroup.name!r}:'
                        f' {rgroup.description!r} → {lgroup.description!r}')
        for group_name, rule in rules_added:
            logger.info(f'  - Create {rule!r} in group {group_name!r}')
        for group_name, rule in rules_removed:
            logger.info(f'  - Remove {rule!r} from group {group_name!r}')
        for group in groups_removed:
            logger.info(f'  - Remove group {group.name!r} with {len(group.rules)} rules')

        if threshold is not None:
            changes_percentage = changes / (unchanged + changes) * 100
            if changes_percentage > threshold:
                raise ThresholdException(f'Amount of changes is {changes_percentage:f}%'
                                         f' which is more than allowed ({threshold:f}%)')

        if dry_run:
            return

        # We've modified 'remote', so copy it again
        remote = OrderedSet(self.remote)
        rgroups, rkeys = parse_groups(remote)

        # Added groups
        for group in groups_added:
            ginfo = self.connection.create_security_group(
                name=group.name,
                description=group.description)
            remote.add(Group.from_remote(**ginfo))
        rgroups, rkeys = parse_groups(remote)

        # Updated groups
        for rgroup, lgroup in groups_updated:
            self.connection.update_security_group(
                name_or_id=rgroup._id,
                description=lgroup.description)
            # Updating group should not change its ID
            rgroup.description = lgroup.description

        # Added rules
        for group_name, rule in rules_added:
            rgroup = rgroups[group_name]
            cidr = str(rule.cidr) if rule.cidr is not None else None
            group_id = rgroups[rule.group]._id if rule.group is not None else None
            rinfo = self.connection.create_security_group_rule(
                secgroup_name_or_id=rgroup._id,
                port_range_min=rule.port_min,
                port_range_max=rule.port_max,
                protocol=rule.protocol.value,
                remote_ip_prefix=cidr,
                remote_group_id=group_id,
                direction=rule.direction.value,
                ethertype=rule.ethertype.value)
            rgroup.rules.add(Rule.from_remote(**rinfo))

        if remove:
            # Removed rules
            for group_name, rule in rules_removed:
                rgroup = rgroups[group_name]
                self.connection.delete_security_group_rule(
                    rule_id=rule._id)
                rgroup.rules.remove(rule)

            # Removed groups
            for group in groups_removed:
                self.connection.delete_security_group(
                    name_or_id=group._id)
                remote.remove(group)

        self.remote = remote
