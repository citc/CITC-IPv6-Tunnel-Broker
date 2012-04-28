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
DDTB XML-RPC IPC daemon implementation
"""

from bjsonrpc.handlers import BaseHandler
from bjsonrpc import createserver
from bjsonrpc.exceptions import ServerError
import bjsonrpc

import base64

import os,sys,re,time,threading
import socket,signal
from select import select
from ddtb import DDTBError
from ddtb.config import DDTBConfig
from ddtb.database import Client, Prefix, Tunnel
from ddtb import crypto

class TBRPCInvalidAPIKEYError(ServerError):
    """
    Error raised by invalid XML-RPC error
    """
    def __str__(self):
        logs.ipc.error("Invalid API key for function %s" % self.args[0])
        return "Invalid API key for function:  " + self.args[0]

    def get(self):
        return "Invalid API key for function:  " + self.args[0]

class TBRPCDDTBError(ServerError):
    """
    Error raised by invalid XML-RPC error
    """
    def __str__(self):
        logs.ipc.error("Invalid API key for function %s" % self.args[0])
        return "Invalid API key for function:  " + self.args[0]

class TBRPCServerHandler(BaseHandler):

    @classmethod
    def _factory(cls, config, database, sessions, prefixes):
       def handler_factory(connection):
           handler = cls(connection, config, database, sessions, prefixes)
           return handler
       return handler_factory

    def __init__(self, connection, config, database, sessions, prefixes):
        BaseHandler.__init__(self,connection)

        self.crypt    = crypto.TBCrypt()
        self.database = database
        self.sessions = sessions
        self.prefixes = prefixes
        self.config   = config
        self.thread   = None
        if (config.ipc.db_key):
          self.db_key = base64.b64decode(config.ipc.db_key)
        else:
          self.db_key = None

    def _checkAPIKey(self,key):
        if key == self.config.ipc.apikey:
            return True
        return False

    def _genericFilter(self, macroobject, keylist, dictkey = None):
        """
        Generic datastore filtering function.
        """
        if not dictkey:
            finalList = []
        else:
            finalDict = {}
            if type(macroobject) == type([]):
                for a in macroobject:
                    tempDict = {}
                    for key in keylist:
                        try:
                            tempDict[key] = a[key]
                        except KeyError:
                            pass
                    if dictkey:
                        finalDict[a[dictkey]] = tempDict
                    else:
                        finalList.append(tempDict)
                if dictkey:
                    return finalDict
                else:
                    return finalList
            else:
                tempDict = {}
                for key in keylist:
                    try:
                        tempDict[key] = macroobject[key]
                    except KeyError:
                        pass
                if dictkey:
                    finalDict[macroobject[dictkey]] = tempDict
                else:
                    finalList.append(tempDict)
                return tempDict

    def _userLogin(self, id):
        """
        Gets the id of the user, can be id, login or prefix
        """

        if filter(lambda x: x.id == id, self.database.clients()):
            return self.database.store.find(Client,Client.id==int(id)).one().login
        elif filter(lambda x: x.login.encode('utf-8') == id.encode('utf-8'), self.database.clients()):
            return id
        elif filter(lambda x: x.prefix == id, self.database.prefixes()):
            return self.database.store.find(Prefix,Prefix.prefix==id).one().client.login

        return None

    #
    # User Management
    #

    def listUsers(self, apikey):
        userList = []
        if self._checkAPIKey(apikey):
            for a in self.database.clients():
                userList.append(a.login)
            logs.ipc.info("Users listed")
            return userList
        else:
            return TBRPCInvalidAPIKEYError('listUsers')

    def addUser(self, apikey, enc_login, enc_name, enc_plaintext_password, email, mobile, ipaddress):
        if self._checkAPIKey(apikey):
            DEFAULT_MIN_PREFIX = 1
            DEFAULT_MAX_PREFIX = 50

            login = base64.b64decode(enc_login).decode('utf-8')
            plaintext_password = base64.b64decode(enc_plaintext_password)
            name = base64.b64decode(enc_name).decode('utf-8')
            iv = self.crypt.get_new_iv()
            if self.db_key is not None:
                passwd = base64.b64encode(self.crypt.encryptPassword(iv, plaintext_password, self.db_key))
            else:
                passwd = plaintext_password

            # TODO, check if user with login already exists
            try:
                self.database.register_client(
                    login      = login,
                    name       = name,
                    iv         = base64.b64encode(iv),
                    passwd     = passwd,
                    email      = email,
                    mobile     = mobile,
                    ipaddress  = ipaddress,
                    min_prefix = DEFAULT_MIN_PREFIX,
                    max_prefix = DEFAULT_MAX_PREFIX,
                )
                self.database.store.autoreload()
                self.sessions.manager.change_user_cache(login)
                logs.ipc.info("User with login %s successfully added" % login)
                return True
            except DDTBError,e:
                logs.ipc.error("User with login %s not added" % login)
                return e
        else:
            return TBRPCInvalidAPIKEYError('addUser')

    def changeUserPassword(self, apikey, id, newPlaintextPassword):
        if self._checkAPIKey(apikey):
            login = self._userLogin(base64.b64decode(id).decode('utf-8'))
            if not login:
                return DDTBError('Client with login %s not found' % login)

            iv = self.crypt.get_new_iv()
            if self.db_key is not None:
                newPassword = base64.b64encode(self.crypt.encryptPassword(iv, base64.b64decode(newPlaintextPassword), self.db_key))
            else:
                newPassword = newPlaintextPassword

            try:
                self.database.update_password(login, base64.b64encode(iv), newPassword)
                self.database.store.autoreload()
                self.sessions.manager.change_user_cache(login)
                logs.ipc.info("Password for user with login %s successfully changed" % login)
                return True
            except DDTBError,e:
                logs.ipc.error("Password for user with login %s NOT changed" % login)
                return e
        else:
            return TBRPCInvalidAPIKEYError('changeUserPassword')

    def removeUser(self, apikey, id):
        if self._checkAPIKey(apikey):
            #try:
            #    killTunnel(self, apikey, login)
            #except:
            #    pass

            login = self._userLogin(base64.b64decode(id).decode('utf-8'))
            if not login:
                return DDTBError('Client with login %s not found' % login)
            try:
                self.database.unregister_client(login=login.encode('utf-8'))
                self.database.store.autoreload()
                if self.sessions.manager.auth.user_cache.has_key(login):
                    del self.sessions.manager.auth.user_cache[login]
                    logs.ipc.debug('User %s removed from user cache.' % login)
                else:
                    logs.ipc.error("User with login %s was NOT found in user cache, could not remove." % (login))
                    return False

                logs.ipc.info("User with login %s successfully removed." % login)
                return True
            except DDTBError,e:
                print 'Error removing user %s: %s' % (login,e)
        else:
            return TBRPCInvalidAPIKEYError('removeUser')

    def userDetails(self, apikey, id):
        if self._checkAPIKey(apikey):
            login = self._userLogin(id)
            if not login:
                return DDTBError('Client with login %s not found' % login)

            client = self.database.client_details(login)
            # Easy client to dict conversion, casting doesn't work
            fieldList =  ['login', 'name', 'email', 'mobile', 'ipaddress']
            clientList = [client.login, client.name, client.email, client.mobile, client.ipaddress]
            return dict(zip(fieldList, clientList))
        else:
            return TBRPCInvalidAPIKEYError('userDetails')

    def checkLogin(self, apikey, login, plaintext_password):
        norm_login = base64.b64decode(login).decode('utf-8')
#        logs.ipc.debug("ipc.checkLogin: look for id for login %s" % (norm_login))
        norm_pass  = base64.b64decode(plaintext_password).decode('utf-8')

        if self._checkAPIKey(apikey):
            if self.db_key is not None:

#                logs.ipc.debug("ipc.checkLogin: has apikey, try to get id")
                id = self._userLogin(norm_login)
#                logs.ipc.debug("ipc.checkLogin: id = %s, try to get client object from database" % (id))

                if id:
                    client = self.database.client_details(id)
                    iv = base64.b64decode(client.iv)
#                    logs.ipc.debug("ipc.checkLogin: got client, IV is %s" % (client.iv))
                else:
                    iv = self.crypt.get_new_iv()   # Just some random IV for non-existent user
                    logs.ipc.warn("ipc.checkLogin: no ID! Login attempt by non-existent user %s." % (norm_login))

#                logs.ipc.debug("ipc.checkLogin: encrypt password")
                password = base64.b64encode(self.crypt.encryptPassword(iv, norm_pass.encode('utf-8'), self.db_key))

            else:
                password = norm_pass

#            logs.ipc.debug("ipc.checkLogin: try database.checkLogin") 
#            retval = self.database.checkLogin(unicode(norm_login), unicode(password.encode('utf-8')))
#            logs.ipc.debug("ipc.checkLogin: return value from database: %s" %(retval)) 
            return self.database.checkLogin(norm_login, password)

        else:
            return TBRPCInvalidAPIKEYError('checkLogin')


    #
    # Tunnel Management
    #

#    def listTunnels(self, apikey, id=None):
#        """
#        Lists currently open tunnels
#        """
#
#        if self._checkAPIKey(apikey):
#
#            tunnels = None
#
#            # Get list of tunnels
#
#            if id:
#                login = self._userLogin(id)
#                if not login:
#                    return DDTBError('Client with login %s not found' % str(login))
#
#                if filter(lambda x: x.login == login, self.database.clients()):
#                    tunnels = self.database.tunnels(self,login)
#                else:
#                    return DDTBError('Client with id %s not found' % str(client_id))
#            else:
#                tunnels = self.database.tunnels()
#
#            # Filter the information to make it nice for XML-RPC
#            VALUELIST = ['client_port' , 'client_ipv4', 'client_ipv6', 'prefix', \
#                         'client_id', 'keepalive', 'start_time', 'valid_until']
#
##            tunnelDict = self._genericFilter(tunnels, VALUELIST, 'prefix')
#
##            return tunnelDict
#            return pformat(dir(tunnels))
#        else:
#            return TBRPCInvalidAPIKEYError('listTunnels')
#
#    def killTunnel(self, apikey, clientPrefixLoginOrID):
#        """
#        Kills the specified tunnel (can refer to tunnel by prefix, user login or client id)
#        """
#
#        if self._checkAPIKey(apikey):
#            if filter(lambda x: x.client_id == clientPrefixLoginOrID, self.database.clients()):
#                tunnels = self.database.tunnels(self,clientPrefixLoginOrID)
#            elif filter(lambda x: x.login == clientPrefixLoginOrID, self.database.clients()):
#                tunnels = self.database.tunnels(self,clientPrefixLoginOrID)
#            elif filter(lambda x: x.prefix == clientPrefixLoginOrID, self.database.prefixes()):
#                tunnels = self.database.tunnels(self,clientPrefixLoginOrID)
#            else:
#                return DDTBError('Tunnel with  id %s not found' % str(clientPrefixLoginOrID))
#
#            for tunnel in tunnels:
#                try:
#                    self.sessions.manager.tunnelconfigs.deconfigure_tunnel(tunnel)
#                    self.database.unregister_tunnel(tunnel.id)
#                    logs.ipc.info("Tunnel with ID# %s removed." % str(tunnel.id))
#                except:
#                    logs.ipc.error("Could not remove tunnel with ID# %s." % str(tunnel.id))
#        else:
#            return TBRPCInvalidAPIKEYError('killTunnel')



class TBRPCServer(object):
    def __init__(self, config, database, sessions, prefixes):
        self.config = config
        self.database = database
        self.sessions = sessions
        self.prefixes = prefixes
        self.thread = None

        # TODO: add ability to bind RPC to alternative IP not just localhost
        self.s = createserver(host=self.config.ipc.rpcip, port=int(self.config.ipc.port), \
                              handler_factory=TBRPCServerHandler._factory(self.config, \
                                                                 self.database, \
                                                                 self.sessions, \
                                                                 self.prefixes))

    def start(self):
        logs.ipc.info("IPC server starting")
        self.thread = threading.Thread(target=self.s.serve)
        self.thread.start()
        logs.ipc.info("IPC server started")


    def stop(self):
        if self.thread:
            logs.ipc.info("IPC server stopping")
            self.s.stop()
            self.thread.join()
            self.thread = None
            logs.ipc.info("IPC server stopped")

def isActive(config):
    try:
        bjsonrpc.connect(host=config.ipc.rpcip, port=int(config.ipc.port))
        return True
    except:
        return False
