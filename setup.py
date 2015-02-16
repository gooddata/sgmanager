#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved

from setuptools import setup

setup(
    name='sgmanager',
    version='1.2.1',
    packages=['sgmanager', 'sgmanager.logger', 'sgmanager.securitygroups'],
    entry_points = {
        'console_scripts': [ 'sgmanager = sgmanager.cli:main' ]
    },
    license='BSD',
    author='Filip Pytloun',
    author_email='filip.pytloun@gooddata.com',
    maintainer='Filip Pytloun',
    maintainer_email='filip@pytloun.cz',
    description='Security Groups Management Tool',
    long_description='Tooling for management of security groups. Load local configuration, load remote groups and apply differences.',
    url='https://github.com/gooddata/sgmanager',
    download_url='https://github.com/gooddata/sgmanager',
    platform='POSIX',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Operating System :: POSIX',
        'Topic :: System :: Networking :: Firewalls',
        'Programming Language :: Python',
        'Programming Language :: Python :: Implementation :: CPython',
    ],
    install_requires=['boto<2.35', 'PyYAML', 'argparse']
)
