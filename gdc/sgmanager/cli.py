#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved

import sys
import argparse
import logging
from gdc.sgmanager import SGManager
import gdc.logger
lg = gdc.logger.init(syslog=False)

def main():
    """
    Main entrance
    """
    parser = argparse.ArgumentParser(description='Security groups management tool')
    parser.add_argument('-c', '--config', help='Config file to use')
    parser.add_argument('--dump', action='store_true', help='Dump remote groups and exit')
    parser.add_argument('-f', '--force', action='store_true', help='Force action (otherwise run dry-run)')
    parser.add_argument('-q', '--quiet', action='store_true', help='Be quiet, print only WARN/ERROR output')
    parser.add_argument('-d', '--debug', action='store_true', help='Debug mode')
    parser.add_argument('--no-remove', action='store_true', help='Do not remove any groups or rules, only add')
    parser.add_argument('--no-remove-groups', action='store_true', help='Do not remove any groups, only add')
    args = parser.parse_args()

    if args.quiet:
        lg.setLevel(logging.WARN)
    else:
        lg.setLevel(logging.INFO)

    if args.debug:
        lg.setLevel(logging.DEBUG)

    manager = SGManager()
    manager.load_remote_groups()

    if args.dump:
        # Only dump remote groups and exit
        print manager.dump_remote_groups()
        sys.exit(0)

    if not args.config:
        lg.error('No config file supplied')
        sys.exit(1)

    manager.load_local_groups(args.config)

    # Parameters for manager.apply_diff()
    params = {
        'dry' : not args.force,
        'remove_rules' : False if args.no_remove else True,
        'remove_groups' : False if args.no_remove_groups or args.no_remove else True,
    }

    manager.apply_diff(**params)