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
Logging functions for the DDTB modules
"""

import os,logging,logging.handlers

from ddtb import DDTBError

LOGGING_DEFAULTS = {
    'logdir':       '/var/log/ddtbs',
    'max_bytes':    2**20,
    'rotations':    8,
}
LOG_DIRECTORY = '/var/log/ddtb'
LOGFORMAT = '%(asctime)s %(name)s[%(process)d] %(levelname)s: %(message)s'

class DDTBLogFile(object):
    """
    Abstraction for one specific writable DDTB logfile
    """
    def __init__(self,program,path,logformat,level,max_bytes,rotations):
        self.program = program
        self.path = path

        handler = logging.handlers.RotatingFileHandler(
            filename=path,
            mode='a+',
            maxBytes = max_bytes,
            backupCount=rotations,
        )
        handler.setFormatter(logging.Formatter(logformat))
        self.logger = logging.getLogger(self.program)
        self.logger.addHandler(handler)
        self.logger.setLevel(level)

    def __getattr__(self,attr):
        try:
            return getattr(self.__dict__['logger'],attr)
        except KeyEror:
            raise AttributeError

class DDTBLogs(dict):
    """
    Initialize the logging facilities available for DDTB
    """
    def __init__(self,config):
        for k,v in config.items():
            setattr(self,k,v)

        if not os.path.isdir(self.logdir):
            raise DDTBError('No such directory: %s' % self.logdir)

        try:
            ddtblog = os.path.join(self.logdir,'ddtb.log')
            self['ddtb'] = DDTBLogFile(
                program='ddtb',
                path=ddtblog,
                logformat=LOGFORMAT,
                level=logging.DEBUG,
                max_bytes=self.max_bytes,
                rotations=self.rotations
            )
        except IOError,(ecode,emsg):
            raise DDTBError('Error opening %s: %s' % (ddtblog,emsg))

        try:
            sessionlog = os.path.join(self.logdir,'session.log')
            self['session'] = DDTBLogFile(
                program='session',
                path=sessionlog,
                logformat=LOGFORMAT,
                level=logging.DEBUG,
                max_bytes=self.max_bytes,
                rotations=self.rotations
            )
        except IOError,(ecode,emsg):
            raise DDTBError('Error opening %s: %s' % (sessionlog,emsg))

        try:
            authlog = os.path.join(self.logdir,'auth.log')
            self['auth'] = DDTBLogFile(
                program='clientauth',
                path=authlog,
                logformat=LOGFORMAT,
                level=logging.DEBUG,
                max_bytes=self.max_bytes,
                rotations=self.rotations
            )
        except IOError,(ecode,emsg):
            raise DDTBError('Error opening %s: %s' % (authlog,emsg))

        try:
            ipclog = os.path.join(self.logdir,'ipc.log')
            self['ipc'] = DDTBLogFile(
                program='ipc',
                path=authlog,
                logformat=LOGFORMAT,
                level=logging.DEBUG,
                max_bytes=self.max_bytes,
                rotations=self.rotations
            )
        except IOError,(ecode,emsg):
            raise DDTBError('Error opening %s: %s' % (ipclog,emsg))

        for f in [ddtblog,sessionlog,authlog,ipclog]:
            if os.geteuid() == self.uid:
                try:
                    os.chmod(f,int('0660',8))
                except IOError,(ecode,emsg):
                    raise DDTBError('Error setting permissions for %s: %s' % (f,emsg))
            s = os.stat(f)
            if s.st_uid != self.uid or s.st_gid != self.gid:
                try:
                    os.chown(f,self.uid,self.gid)
                except IOError,(ecode,emsg):
                    raise DDTBError('Error setting permissions for %s: %s' % (f,emsg))

    def __getattr__(self,log):
        """
        Attempts to return a log target from our dictionary
        """
        try:
            return self[log]
        except KeyError:
            raise AttributeError('No such log target: %s' % log)
