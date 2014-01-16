# -*- coding: utf-8 -*-
# Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved

import sys
import os
import argparse
import logging
from urlparse import urlparse

import boto

from sgmanager import SGManager
import sgmanager.logger

lg_root = sgmanager.logger.init(name='', syslog=False)
lg = logging.getLogger('gdc.sgmanager')

def main():
    """
    Main entrance
    """
    try:
        cli()
    except (KeyboardInterrupt, SystemExit):
        # User interruption
        sys.exit(1)
    except Exception as e:
        if getattr(e, 'friendly', False):
            # Friendly exceptions - just log and exit
            lg.error(e)
            sys.exit(1)
        else:
            # Evil exceptions, print stack trace
            raise

def cli():
    """
    Main CLI entrance
    """
    parser = argparse.ArgumentParser(description='Security groups management tool')
    parser.add_argument('-c', '--config', help='Config file to use')
    parser.add_argument('--dump', action='store_true', help='Dump remote groups and exit')
    parser.add_argument('-f', '--force', action='store_true', help='Force action (otherwise run dry-run)')
    parser.add_argument('-q', '--quiet', action='store_true', help='Be quiet, print only WARN/ERROR output')
    parser.add_argument('-d', '--debug', action='store_true', help='Debug mode')
    parser.add_argument('--no-remove', action='store_true', help='Do not remove any groups or rules, only add')
    parser.add_argument('--no-remove-groups', action='store_true', help='Do not remove any groups, only add')
    parser.add_argument('--ec2-access-key', help='EC2 Access Key to use')
    parser.add_argument('--ec2-secret-key', help='EC2 Secret Key to use')
    parser.add_argument('--ec2-region', help='Region to use (default us-east-1)', default='us-east-1')
    parser.add_argument('--ec2-url', help='EC2 API URL to use (otherwise use default)')
    args = parser.parse_args()

    if args.quiet:
        lg.setLevel(logging.WARN)
        lg_root.setLevel(logging.WARN)
    else:
        lg.setLevel(logging.INFO)
        lg_root.setLevel(logging.INFO)

    if args.debug:
        lg.setLevel(logging.DEBUG)
        lg_root.setLevel(logging.DEBUG)

    # Initialize SGManager
    ec2 = connect_ec2(args)
    manager = SGManager(ec2)
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

def connect_ec2(args):
    """
    Connect to EC2 API by supplied arguments.
    Return EC2 connection object.
    """
    # Prepare EC2 connection parameters
    if not args.ec2_access_key:
        if os.getenv('EC2_ACCESS_KEY'):
            args.ec2_access_key = os.getenv('EC2_ACCESS_KEY')
        elif os.getenv('AWS_ACCESS_KEY'):
            args.ec2_access_key = os.getenv('AWS_ACCESS_KEY')
        else:
            lg.error("EC2 Access Key not supplied. Use EC2_ACCESS_KEY or AWS_ACCESS_KEY environment variables or command line option")
            sys.exit(1)

    if not args.ec2_secret_key:
        if os.getenv('EC2_SECRET_KEY'):
            args.ec2_secret_key = os.getenv('EC2_SECRET_KEY')
        elif os.getenv('AWS_SECRET_KEY'):
            args.ec2_secret_key = os.getenv('AWS_SECRET_KEY')
        else:
            lg.error("EC2 Secret Key not supplied. Use EC2_SECRET_KEY or AWS_SECRET_KEY environment variables or command line option")
            sys.exit(1)

    if not args.ec2_url:
        if os.getenv('EC2_URL'):
            args.ec2_url = os.getenv('EC2_URL')

    # Connect to EC2
    if args.ec2_url:
        # Special connection to EC2-compatible API (eg. OpenStack)
        ec2_url_parsed = urlparse(args.ec2_url)
        is_secure = False if ec2_url_parsed.scheme == "http" else True

        region = boto.ec2.regioninfo.RegionInfo(name=args.ec2_region, endpoint=ec2_url_parsed.netloc)
        lg.debug("Connecting to host=%s, port=%s, path=%s, region=%s, SSL=%s" % (ec2_url_parsed.hostname, ec2_url_parsed.port, ec2_url_parsed.path, region.name, is_secure))
        ec2 = boto.connect_ec2(aws_access_key_id=args.ec2_access_key,
                               aws_secret_access_key=args.ec2_secret_key,
                               is_secure=is_secure,
                               region=region,
                               host=ec2_url_parsed.hostname,
                               # when I use port parameter, it will be duplicated for unknown reason
                               # port=ec2_url_parsed.port,
                               path=ec2_url_parsed.path)
    else:
        # Standard connection to AWS EC2
        ec2 = boto.ec2.connect_to_region(args.ec2_region,
                                         aws_access_key_id=args.ec2_access_key,
                                         aws_secret_access_key=args.ec2_secret_key)

    return ec2
