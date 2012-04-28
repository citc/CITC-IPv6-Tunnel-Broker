#!/usr/bin/env python

 # Copyright (C) CITC, Communications and Information Technology Commission,
 # Kingdom of Saudi Arabia.
 #
 # Developed by CITC Tunnel Broker team, tunnelbroker@citc.gov.sa.
 #
 # This software is released to public domain under GNU General Public License
 # version 2, June 1991 or any later. Please see file 'LICENSE' in source code
 # repository root.

import glob
from setuptools import setup, find_packages

setup(
    name = 'ddtb',
    version = '1.0',
    description = 'ddtb, a TSP-compliant tunnel broker',
    author = 'CITC', 
    author_email = 'tunnelbroker@citc.gov.sa',
    url = 'http://www.ipv6.sa/tunnelbroker/',
    packages = find_packages('src'),
    package_dir = {'':'src'},
    scripts = glob.glob('bin/*'),

    zip_safe = False,
    install_requires = ['configobj',
                        'md.py',
                        'mysql-python',
                        'storm',
                        'bjsonrpc',
                        'tornado',
                        'formencode'],
    license = 'GPL',
    keywords = 'IPv6 over IPv4 tunnel broker TSP ddtb',
    long_description = """\
    ddtb is implementation of TSP. It works with utun kernel module,
    adding and removing interfaces that handle IPv6 over UDP/IPv4
    tunneling (encapsulation/decapsulation). Rudimentary management
    with ddtbmanage.""",

    classifiers = [
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Programming Language :: Python",
        "Development Status :: 4 - Beta",
        "Environment :: No Input/Output (Daemon)",
        "Operating System :: POSIX :: Linux",
        "Topic :: System :: Networking",
    ],
)   
