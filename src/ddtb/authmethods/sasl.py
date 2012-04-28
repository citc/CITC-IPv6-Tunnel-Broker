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
Module for DDTB SASL authentication handling
"""

import base64
from storm.locals import *

from ddtb import DDTBError
from ddtb.auth import DDTBAuthenticator 
from ddtb.authmethods.backends.mod_sasl import DigestMD5,DigestMD5Password,SimpleAuth

class saslAuthentication(DDTBAuthenticator):
    def __init__(self,config):
        DDTBAuthenticator.__init__(self,config)
        self.method = 'DIGEST-MD5'
        self.service = 'tsp'
        try:
            self.server = config.auth.server
        except KeyError:
            raise DDTBError('SASL server address not configured.')

    def __str__(self):
        return '%s service for %s authentication from %s' % (
            self.service,self.method,self.server
        )

    def get_service(self):
        return self.service

    def get_host(self):
        return self.server

    def challenge(self):
        """
        Create a DIGEST-MD5 challenge, encoded to base64, returning the 
        encoded challenge and MD5 hash.
        """
        #logs.ddtb.debug('Challenge for service %s on %s' % (
        #    self.service,self.server
        #))
        md5 = DigestMD5( SimpleAuth(
            DigestMD5Password,
            dict(self.user_cache),
            None,
            None,
            self.get_service,
            self.get_host
        ))
        authstate = md5.challenge()
        encoded = ''.join(authstate.data.encode('base64').split('\n'))
        return (encoded,md5)

    def response(self,md5,encoded):
        """
        Calculate DIGEST-MD5 hash from base64 encoded response. Verifying
        if it matches user details is done by caller so we don't mess up
        with database connections here.
        """
        try:
            response = encoded.decode('base64')
#            logs.auth.debug('Decoded client response: %s' % (response))
        except ValueError:
            logger.info('Invalid base64 encoded data')
        authstate = md5.verify(None,response)
        user_response = ''.join(authstate.data.encode('base64').split('\n'))
        return (authstate,user_response)

