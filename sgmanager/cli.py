# SPDX-License-Identifier: BSD-3-Clause
# Copyright © 2013-2018, GoodData Corporation. All rights reserved.

import argparse
import logging
import pathlib
import sys

import openstack
from openstack.config import OpenStackConfig

from .manager import SGManager
from .utils import dump_groups, validate_groups

logging.basicConfig(level=logging.ERROR)
LOGGER = logging.getLogger('sgmanager')
LOGGER_HANDLER = logging.StreamHandler()
LOGGER_FORMATTER = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
LOGGER_HANDLER.setFormatter(LOGGER_FORMATTER)
LOGGER.addHandler(LOGGER_HANDLER)
LOGGER.setLevel(logging.INFO)

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    config = OpenStackConfig()

    parser = argparse.ArgumentParser()
    config.register_argparse_arguments(parser, argv)

    parser.add_argument('-d', '--debug', action='store_true',
                        help='Enable debugging')

    cmd = parser.add_subparsers(
        title='Available Commands',
        dest='command',
    )
    cmd.required = True

    cmd_dump = cmd.add_parser(
        'dump',
        help='Dump configuration',
    )
    cmd_dump.add_argument(
        'config',
        nargs='?',
        type=pathlib.Path,
    )

    def dump(manager, args):
        if args.config is None:
            # Dump remote groups
            manager.connection = openstack.connect(config=args)
            manager.load_remote_groups()
            groups = manager.remote
        else:
            # Dump local groups
            manager.load_local_groups(args.config)
            groups = manager.local
            validate_groups(groups)

        print(dump_groups(groups, default_flow_style=False, width=-1))

    cmd_update = cmd.add_parser(
        'update',
        help='Update configuration',
    )
    cmd_update.add_argument(
        '-f', '--force',
        dest='dry_run',
        action='store_false',
        help='Disable dry-run mode',
    )
    cmd_update.add_argument(
        '-t', '--threshold',
        type=int,
        default=15,
        help='Maximum threshold to us for adding/removing'
             ' groups/rules in a percentage')
    cmd_update.add_argument(
        '--no-remove',
        dest='remove',
        action='store_false',
        help='Do not remove any groups or rules')
    cmd_update.add_argument(
        'config',
        type=pathlib.Path,
    )

    def update(manager, args):
        manager.connection = openstack.connect(config=args)
        manager.load_local_groups(args.config)
        manager.load_remote_groups()
        manager.update_remote_groups(dry_run=args.dry_run,
                                     threshold=args.threshold,
                                     remove=args.remove)

    args = parser.parse_args()
    if args.debug:
        LOGGER.setLevel(logging.DEBUG)

    manager = SGManager()
    locals()[args.command](manager, args)
