#!/usr/bin/env python

 # Copyright (C) CITC, Communications and Information Technology Commission,
 # Kingdom of Saudi Arabia.
 #
 # Developed by CITC Tunnel Broker team, tunnelbroker@citc.gov.sa.
 #
 # This software is released to public domain under GNU General Public License
 # version 2, June 1991 or any later. Please see file 'LICENSE' in source code
 # repository root.

"""
Module for parsing and configuring the tunnelbroker configuration.
"""

import os,sys,re,configobj
import pwd,grp
from subprocess import call,Popen,PIPE

from ddtb import DDTBError
from ddtb.logs import DDTBLogs
from ddtb.address import IPv4Address,IPv6Address

DEFAULT_CLEANUP_INTERVAL   = 86400
DEFAULT_KEEPALIVE_INTERVAL = 30

DEFAULT_PREFIX_SIZE        = 64

DEFAULT_CONFIG_PATH = "/etc/ddtb/ddtb.cfg"

DEFAULT_LOG_DIRECTORY = '/var/log/ddtb'
DEFAULT_LOG_ROTATIONS = 10
DEFAULT_LOG_MAX_BYTES = 4194304
DEFAULT_LOG_OWNER = 'ddtb'
DEFAULT_LOG_GROUP = 'ddtb'

MAX_ROTATIONS = 1000
LOG_BYTES_LIMIT = 2**29

BROKER_REQUIRED_CONFIG_KEYS = [ 'hostname', 'tunnelip', 'serverip', 'port', ]
AUTH_REQUIRED_CONFIG_KEYS = [ 'method', 'server', ]

# Commands to prepare TTDB kernel and iptables for use
TTDB_INIT_COMMANDS = [
    "sysctl -q -w net.ipv4.conf.all.forwarding=1",
    "sysctl -q -w net.ipv4.ip_forward=1",
    "sysctl -q -w net.ipv6.conf.all.forwarding=1",
    "sysctl -q -w net.ipv4.conf.all.accept_local=1",
    "sysctl -q -w net.ipv4.conf.default.accept_local=1",
    "sysctl -q -w net.ipv4.conf.default.rp_filter=0",
    "sysctl -q -w net.ipv4.conf.all.rp_filter=0",
    "iptables -t raw -A PREROUTING -p udp --dport 3653 -m u32 --u32 " +
      " 28&0xf0000000=0xf0000000 -j RAWDNAT --to-destination %(serverip)s",
    "iptables -t rawpost -A POSTROUTING -p udp --sport 3653 -m u32 --u32" +
      " 28&0xf0000000=0xf0000000 -j RAWSNAT --to %(tunnelip)s",
]

TTDB_CLEANUP_COMMANDS = [
    # We don't reset sysctl config to any previous value: we don't know the
    # original or wanted sysctl values to reset in the first place
    "iptables -t raw -D PREROUTING -p udp --dport 3653 -m u32 --u32 " +
      " 28&0xf0000000=0xf0000000 -j RAWDNAT --to-destination %(serverip)s",
    "iptables -t rawpost -D POSTROUTING -p udp --sport 3653 -m u32 --u32" +
      " 28&0xf0000000=0xf0000000 -j RAWSNAT --to %(tunnelip)s",
]

def validate_hostname(value):
    """
    Validate a hostname according to a bit relaxed standards in naming.
    Does not support IDN names!
    """
    re_part = re.compile(r'^[a-z0-9]+[a-z0-9_-]*[a-z0-9]+$')
    parts = value.split('.')
    if len(parts) < 2:
        raise ValueError
    for p in parts:
        if not re_part.match(p):
            raise ValueError

class DDTBConfigSection(dict):
    def __init__(self,name,data):
        self.name = name
        self.update(data)

    def __getattr__(self,attr):
        try:
            return self[attr]
        except KeyError:
            raise AttributeError('No such %s config item: %s' % (self.name,attr))

class DDTBLoggingConfig(DDTBConfigSection):
    def __init__(self,name,data):
        DDTBConfigSection.__init__(self,name,data)

        if not self.has_key('logdir'):
            self['logdir'] = DEFAULT_LOG_DIRECTORY
        if not self.has_key('rotations'):
            self['rotations'] = DEFAULT_LOG_ROTATIONS
        if not self.has_key('max_bytes'):
            self['max_bytes'] = DEFAULT_LOG_MAX_BYTES
        if not self.has_key('owner'):
            self['owner'] = DEFAULT_LOG_OWNER
        if not self.has_key('group'):
            self['group'] = DEFAULT_LOG_GROUP

        try:
            self['uid'] = pwd.getpwnam(str(self['owner']).strip()).pw_uid
        except KeyError:
            raise DDTBError('User for logs %s not found.' % self.owner)
        try:
            self['gid'] = grp.getgrnam(str(self['group']).strip()).gr_gid
        except KeyError:
            raise DDTBError('Group for logs %s not found.' % self.group)

        try:
            self['rotations'] = int(self['rotations'])
            if self.rotations<0 or self.rotations > MAX_ROTATIONS:
                raise ValueError
        except ValueError:
             raise DDTBError('Invalid logging rotations value: %s' % self['rotations'])
        try:
            self['max_bytes'] = int(self['max_bytes'])
            if self.max_bytes < 1024 or self.max_bytes > LOG_BYTES_LIMIT:
                raise ValueError
        except ValueError:
             raise DDTBError('Invalid logging max_bytes value: %s' % self['max_bytes'])

        if not os.path.isdir(self['logdir']):
            raise DDTBError('No such directory: %s' % self.logdir)

class DDTBDatabaseConfig(DDTBConfigSection):
    def __init__(self,name,data):
        DDTBConfigSection.__init__(self,name,data)
        if self.engine == 'mysql':
            try:
                self.connection = 'mysql://%(user)s:%(password)s@%(host)s:%(port)s/%(database)s' % self
            except KeyError:
                raise DDTBError('Database configuration missing required values.')
        else:
            raise NotImplementedError('Only MySQL is supported for now.')

class DDTBAuthConfig(DDTBConfigSection):
    def __init__(self,name,data):
        DDTBConfigSection.__init__(self,name,data)

class DDTBClientConfig(DDTBConfigSection):
    def __init__(self,name,data):
        DDTBConfigSection.__init__(self,name,data)

class DDTBIPCConfig(DDTBConfigSection):
    def __init__(self,name,data):
        DDTBConfigSection.__init__(self,name,data)

        try:
            self['active'] = bool(self['active'])
        except KeyError:
            raise DDTBError('RPC "active" flag required')

        if self['active'] and not (self.has_key('apikey') or len(self['apikey'] == 0)):
            raise DDTBError('RPC api key required')

        try:
            self['rpcip'] = IPv4Address(self['rpcip']).ipaddress
        except ValueError:
            raise DDTBError('Invalid broker %s: %s' % (k,self[k]))

        try:
            port = int(self['port'])
            if port <= 0 or port >= 2**16:
                raise ValueError
            self['port'] = port
        except ValueError:
            raise DDTBError('Invalid XML-RPC IPC port: %s' % self['port'])


class DDTBBrokerConfig(DDTBConfigSection):
    def __init__(self,name,data):
        DDTBConfigSection.__init__(self,name,data)

        for opt in BROKER_REQUIRED_CONFIG_KEYS:
            if not self.has_key(opt):
                raise DDTBError('Missing broker configuration for %s' % opt)

        try:
            validate_hostname(self['hostname'])
        except ValueError:
            raise DDTBError('Invalid broker hostname: %s' % self['hostname'])
        for k in ['tunnelip','serverip']:
            try:
                self[k] = IPv4Address(self[k]).ipaddress
            except ValueError:
                raise DDTBError('Invalid broker %s: %s' % (k,self[k]))
        try:
            port = int(self['port'])
            if port <= 0 or port >= 2**16:
                raise ValueError
            self['port'] = port
        except ValueError:
            raise DDTBError('Invalid broker port: %s' % self['port'])

        if not self.has_key('cleanup_interval'):
            self['cleanup_interval'] = DEFAULT_CLEANUP_INTERVAL
        try:
            self['cleanup_interval'] = int(self['cleanup_interval'])
        except ValueError:
            raise DDTBError('Invalid broker cleanup_interval %s' % self['cleanup_interval'])

        if not self.has_key('keepalive_interval'):
            self['keepalive_interval'] = DEFAULT_KEEPALIVE_INTERVAL
        try:
            self['keepalive_interval'] = int(self['keepalive_interval'])
        except ValueError:
            raise DDTBError('Invalid broker keepalive_interval %s' % self['keepalive_interval'])

class DDTBPrefixConfig(DDTBConfigSection):
    def __init__(self,name,data):
        DDTBConfigSection.__init__(self,name,data)

        if not self.has_key('allocation_prefix'):
            raise DDTBError('Missing IPv6 client allocation prefix.')

        try:
            IPv6Address(self['allocation_prefix']).address
        except ValueError:
            raise DDTBError('Invalid IPv6 allocation prefix: %s' % self['allocation_prefix'])

        if not self.has_key('customer_prefix_size'):
            self['customer_prefix_size'] = DEFAULT_PREFIX_SIZE
        try:
            customer_prefix_size = int(self['customer_prefix_size'])
            if customer_prefix_size<=1 or customer_prefix_size>=2**7:
                raise ValueError
            self['customer_prefix_size'] = customer_prefix_size
        except ValueError:
            raise DDTBError('Invalid customer prefix size %s' % self['customer_prefix_size'])


class DDTBConfig(dict):
    def __init__(self,config_path=DEFAULT_CONFIG_PATH):
        if not os.path.isfile(config_path):
            raise DDTBError('No such file: %s' % config_path)

        try:
            config = configobj.ConfigObj(config_path)
        except configobj.ParseError,e:
            raise DDTBError(e)
        except IOError,(ecode,emsg):
            raise DDTBError('Error opening %s: %s' % (config_path,emsg))

        if not config.has_key('broker'):
            raise DDTBError('No broker configuration section.')
        self['broker'] = DDTBBrokerConfig('broker',config['broker'])

        if not config.has_key('prefix'):
            raise DDTBError('No prefix configuration section.')
        self['prefix'] = DDTBPrefixConfig('prefix',config['prefix'])

        if not config.has_key('database'):
            raise DDTBError('No database configuration section.')
        self['database'] = DDTBDatabaseConfig('database',config['database'])

        if not config.has_key('auth'):
            raise DDTBError('No authentication configuration section.')
        self['auth'] = DDTBAuthConfig('auth',config['auth'])

        if not config.has_key('ipc'):
            raise DDTBError('No IPC configuration section.')
        self['ipc'] = DDTBIPCConfig('ipc',config['ipc'])

        if config.has_key('logging'):
            self['logging'] = DDTBLoggingConfig('logging',config['logging'])
        else:
            self['logging'] = DDTBLoggingConfig('logging',{})

        if config.has_key('client'):
            self['client'] = DDTBClientConfig('client',config['client'])
        else:
            self['client'] = DDTBLoggingConfig('logging',{})

        if config.has_key('logging'):
            self['logging'] = DDTBLoggingConfig('logging',config['logging'])
        else:
            self['logging'] = DDTBLoggingConfig('logging',{})

        # Set logging as global reference
        import __builtin__
        __builtin__.logs = DDTBLogs(self['logging'])

    def __getattr__(self,attr):
        try:
            return self[attr]
        except KeyError:
            raise AttributeError('No such DDTBConfig attribute: %s' % attr)

    def init_system(self):
        for cmd in TTDB_INIT_COMMANDS:
            cmd = cmd % self.broker
            logs.ddtb.debug('Running: %s' % cmd)
            retval = call(cmd.split())
            if retval != 0:
                raise DDTBError('Error running command %s' % cmd)

    def cleanup_system(self):
        for cmd in TTDB_CLEANUP_COMMANDS:
            cmd = cmd % self.broker
            logs.ddtb.debug('Running: %s' % cmd)
            retval = call(cmd.split())
            if retval != 0:
                logs.ddtb.debug('Error running command %s' % cmd)
