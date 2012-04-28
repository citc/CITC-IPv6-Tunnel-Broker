#!/usr/bin/python

 # Copyright (C) CITC, Communications and Information Technology Commission,
 # Kingdom of Saudi Arabia.
 #
 # Developed by CITC Tunnel Broker team, tunnelbroker@citc.gov.sa.
 #
 # This software is released to public domain under GNU General Public License
 # version 2, June 1991 or any later. Please see file 'LICENSE' in source code
 # repository root.

"""
Generic authentication method processing
"""

import base64
from storm.locals import *

from ddtb import DDTBError
from ddtb.config import DDTBConfig

def DDTBLoadAuthenticator(config):
    method = config.auth.method
    path = 'ddtb.authmethods.%s' % method
    classname = '%sAuthentication' % method
    m = __import__(path,globals(),fromlist=[method])
    return getattr(m,classname)(config)
    try:
        pass
    except (ImportError,AttributeError):
        raise DDTBError('Error loading authenticator for %s' % method)

class DDTBUserCache(dict):
    """
    Cache of username/password pairs from the database. To update, just 
    pass user records from database to update
    """
    def __getattr__(self,attr):
        try:
            return self[attr]
        except KeyError:
            raise AttributeError('No such user in user cache: %s' % attr)

    def update(self,users):
        """
        Update the user cache from database results. This is actually called
        from ClientSessionManager.
        """
        dict.update(self,{})
        for entry in users:
            self[entry.login] = entry.passwd

class DDTBAuthenticator(object):
    """
    Base class to inherit in authmethods/<authentication_type>.py modules.

    Not flexible, designed for DIGEST-MD5. Fix when you need to add new
    subclasses...
    """ 
    def __init__(self,config):
        self.config = config
        self.method = 'UNDEFINED'
        self.user_cache = DDTBUserCache()

    def __str__(self): 
        return '%s service for %s authentication' % (
            self.service,self.method,self.server
        )

    def challenge(self):
        raise NotImplementedError('Not implemented in base class %s ' % type(self))

    def response(hash,encoded):
        raise NotImplementedError('Not implemented in base class %s ' % type(self))

