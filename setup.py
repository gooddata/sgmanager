#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved

from setuptools import setup

setup(
    name='sgmanager',
    version='1.1',
    packages=['sgmanager', 'sgmanager.logger', 'sgmanager.securitygroups'],
    entry_points = {
        'console_scripts': [ 'sgmanager = sgmanager.cli:main' ]
    },
    url='https://github.com/gooddata/sgmanager',
    license='BSD',
    author='Filip Pytloun',
    author_email='filip.pytloun@gooddata.com',
    description='Security Groups Management Tool',
    requires=['boto', 'yaml', 'argparse']
)
