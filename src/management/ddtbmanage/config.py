#!/usr/bin/env python

 # Copyright (C) CITC, Communications and Information Technology Commission,
 # Kingdom of Saudi Arabia.
 #
 # Developed by CITC Tunnel Broker team, tunnelbroker@citc.gov.sa.
 #
 # This software is released to public domain under GNU General Public License
 # version 2, June 1991 or any later. Please see file 'LICENSE' in source code
 # repository root.

# -*- coding: utf-8 -*-
"""
Module for parsing and configuring the tunnelbroker configuration.
"""

import os,sys,re,configobj
import pwd,grp

from ddtbmanage import DDTBError
#from ddtbmanage.logs import DDTBLogs
from ddtbmanage.address import IPv4Address,IPv6Address

DEFAULT_CLEANUP_INTERVAL   = 86400
DEFAULT_KEEPALIVE_INTERVAL = 30

DEFAULT_PREFIX_SIZE        = 64

DEFAULT_CONFIG_PATH = "/etc/ddtb/ddtbmanage.cfg"

DEFAULT_LOG_DIRECTORY = '/var/log/ddtbmanage'
DEFAULT_LOG_ROTATIONS = 10
DEFAULT_LOG_MAX_BYTES = 4194304
DEFAULT_LOG_OWNER = 'ddtb'
DEFAULT_LOG_GROUP = 'ddtb'

MAX_ROTATIONS = 100
LOG_BYTES_LIMIT = 2**28


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

class DDTBWebSrvConfig(DDTBConfigSection):
    def __init__(self,name,data):
        DDTBConfigSection.__init__(self,name,data)

        if not self.has_key('ip'):
            raise DDTBError('Webserver binding IP required')
        if not self.has_key('port'):
            raise DDTBError('Webserver binding port required')
        if not self.has_key('securecookie'):
            raise DDTBError('Secure cookie required')

        try:
            self['ip'] = IPv4Address(self['ip']).ipaddress
        except ValueError:
            raise DDTBError('Invalid IP address for server %s: %s' % (k,self[k]))

        try:
            port = int(self['port'])
            if port<=0 or port>=2**16:
                raise ValueError
            self['port'] = port
        except ValueError:
            raise DDTBError('Invalid Web Server listening port: %s' % self['port'])

        self['securecookie'] = str(self['securecookie'])

class DDTBAdminLogin(DDTBConfigSection):
    def __init__(self,name,data):
        DDTBConfigSection.__init__(self,name,data)

        if not self.has_key('configfile'):
            raise DDTBError('Config file required')
        elif not os.path.exists(self['configfile']):
            error = 'Config file ' + self.configfile + ' not found.'
            raise DDTBError(error)


class DDTBIPCConfig(DDTBConfigSection):
    def __init__(self,name,data):
        DDTBConfigSection.__init__(self,name,data)

        try:
            self['rpcip'] = IPv4Address(self['rpcip']).ipaddress
        except ValueError:
            raise DDTBError('Invalid broker %s: %s' % (k,self[k]))

        try:
            port = int(self['port'])
            if port<=0 or port>=2**16:
                raise ValueError
            self['port'] = port
        except ValueError:
            raise DDTBError('Invalid XML-RPC IPC port: %s' % self['port'])

class DDTBManageConfig(dict):
    def __init__(self,config_path=DEFAULT_CONFIG_PATH):
        if not os.path.isfile(config_path):
            raise DDTBError('No such file: %s' % config_path)
        try:
            config = configobj.ConfigObj(config_path)
        except configobj.ParseError,e:
            raise DDTBError(e)
        except IOError,(ecode,emsg):
            raise DDTBError('Error opening %s: %s' % (config_path,emsg))

        if not config.has_key('admin'):
            raise DDTBError('No admin user configuration section.')
        self['admin'] = DDTBAdminLogin('admin',config['admin'])

        if not config.has_key('websrv'):
            raise DDTBError('No Web Server configuration section.')
        self['websrv'] = DDTBWebSrvConfig('websrv',config['websrv'])

        if not config.has_key('ipc'):
            raise DDTBError('No IPC configuration section.')
        self['ipc'] = DDTBIPCConfig('ipc',config['ipc'])

        #if config.has_key('logging'):
        #    self['logging'] = DDTBLoggingConfig('logging',config['logging'])
        #else:
        #    self['logging'] = DDTBLoggingConfig('logging',{})


        # Set logging as global reference
        #import __builtin__
        #__builtin__.logs = DDTBLogs(self['logging'])

    def __getattr__(self,attr):
        try:
            return self[attr]
        except KeyError:
            raise AttributeError('No such DDTBConfig attribute: %s' % attr)
