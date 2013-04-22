#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved

from distutils.core import setup

setup(
    name='sgmanager',
    version='1.0',
    packages=['gdc', 'gdc.logger', 'gdc.sgmanager', 'gdc.sgmanager.securitygroups'],
    scripts=['bin/sgmanager.py'],
    url='https://github.com/gooddata/sgmanager',
    license='BSD',
    author='Filip Pytloun',
    author_email='filip.pytloun@gooddata.com',
    description='Security Groups Management Tool',
    requires=['boto', 'yaml', 'argparse']
)