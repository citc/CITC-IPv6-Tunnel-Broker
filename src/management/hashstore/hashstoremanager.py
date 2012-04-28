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

import os, sys, getpass, random, string, site
import base64
from optparse import OptionParser
from pprint import pprint
from datetime import datetime
from ConfigParser import RawConfigParser
from Crypto.Hash import SHA256
from ddtb import crypto
from filelock import FileLock

#
# Global Default config
#
# NOTE: Set USECRACKLIB to True ONLY when it is installed and working properly

LOCATION       = '/etc/ddtb/ddtbmanage-hashstore.dat'
CONFIGFILE     = '/etc/ddtb/ddtbmanage-hashstore.cfg'
DEFAULTSIZE    = 50
USECRACKLIB    = False

#
# Custom hash store
#
class HashStoreException(Exception):
     def __init__(self, value):
         self.value = value
     def __str__(self):
         return repr(self.value)

#
# Helper functions
#
def safePassword(password):
     """Checks if a password is strong through cracklib"""
     try:
          from cracklib import VeryFascistCheck
     except ImportError:
          print "ERROR: cracklib not available. Either install python cracklib or set USECRACKLIB to 'False'"
          sys.exit(-20)
     
     try:
          VeryFascistCheck(password)
          return None
     except ValueError as e:
          return str(e)

def randomPassword(length=DEFAULTSIZE):
     """Generates a random password and if USECRACKLIB is set to True, will ensure it is strong"""
#     d = [random.choice(''.join(list(set(string.printable) - set(string.whitespace) - set(('#','\'','"','{','}','|','&','~','!','[',']','(','),','^'))))) for x in xrange(length)]
     d = [random.choice(''.join(list(set(string.ascii_letters) | set(string.digits) | set('!') ))) for x in xrange(length)]
     password = "".join(d)
     
     # Ensure our password is tight
     if USECRACKLIB:     
          while safePassword(password):
#               d = [random.choice(''.join(list(set(string.printable) - set(string.whitespace) - set(('#','\'','"','{','}','|','&','~','!','[',']','(','),','^'))))) for x in xrange(length)]
               d = [random.choice(''.join(list(set(string.ascii_letters) | set(string.digits) | set('!') ))) for x in xrange(length)]
               password = "".join(d)
          
     return password

#
# Hash store class definition
#
class HashStore():
     def __init__(self, hashfile=LOCATION, storeKey="", configFile=CONFIGFILE):
          self.userDict = { }                       # Mapping of username -> salt:hash
          self.hashfile = hashfile                  # Encrypted file, contains lines of user:salt:hash 
          self.h = SHA256.new()
          self.crypto = crypto.TBCrypt()            # AES encryption/IV functions
          self.storeKey = storeKey                  # Key material to open encrypted hash store
          if configFile:
               try:
                   fp = open(configFile)
               except IOError as e:
                   error = 'IOError: can''t access file ''%s'' (%s).' % (configFile, os.strerror(e.errno))
                   raise HashStoreException(error)
          
               config = RawConfigParser()
               config.read(configFile)
               self.storeKey = config.get('hashstore', 'key')
               self.hashfile = config.get('hashstore', 'location')
          else:
               if os.path.exists(self.hashfile):
                    self.updateUserDict()
               else:
                    self.__saveHashstore()

          if self.storeKey == '':
               print "WARNING: hashstoremanager.py: no hashstore key defined!"

#          print "h.update"
          self.h.update(self.storeKey)
#          print "self.storeKey = self.h.digest()"
          self.storeKey = self.h.digest()
#          print "self.storeKey = %s" % self.storeKey
     
     def __fetchData(self):
          """Private method to grab data from the hashstore"""
          if not os.path.exists(self.hashfile):
               error = "Hash store %s not found." % (self.hashfile)
               raise HashStoreException(error)
          
          data = { }
          try:
               fp = open(self.hashfile, 'r')
#               print "Using key %s to open hash store" % self.storeKey
               plain_hashfile = self.crypto.decryptWithoutIV(fp.read(), self.storeKey)
#               print "foo plain_hashfile in __fetchData: %s" % plain_hashfile
               for line in plain_hashfile.split(' '):
                   lp = line.split(':')
                   if len(lp) > 1:
                       data[lp[0]] = lp[1] + ':' + lp[2]
          except IOError as e:
               fp.close()
               error = 'IOError: can''t access file ''%s'' (%s).' % (self.hashfile, os.strerror(e.errno))
               raise HashStoreException(error)

          fp.close()
          return data
     
     def __saveHashstore(self):
          """Private method to write data out to the hashstore"""
     
          with FileLock(self.hashfile):
              # work with the file as it is now locked
               users = ''
#               print "foo __saveHashstore: self.hashfile = %s" % (self.hashfile)
               with open(self.hashfile, 'w') as f:
                   for line in [ (k + ':' + v + ' ') for k, v in self.userDict.iteritems() ]:
                       users += line

                   f.write(self.crypto.encryptWithoutIV(users, self.storeKey))

     def updateUserDict(self):
          """Updates the internal hashstore cache"""
          self.userDict = self.__fetchData()

     def userExist(self, username, update=True):
          """Check if the user exists in the hashstore. Parameter 'update' (default: True)
             ensures that the hashstore cache is up to date"""
          
#          print "foo userExist: self.userDict.keys() = %s " % self.userDict.keys()
#          print "foo userExist: check if %s in userdict" % (username)

          if update:
               self.updateUserDict()

          if username.encode('utf-8') in self.userDict.keys():
#               print "foo userExist: user found in userDict"
               return True
          return False

     def verifyPassword(self, username, password, update=True):
          """Validate user/password pair is correct"""
          
          if update:
               self.updateUserDict()
          
          if self.userExist(username):
#               print "verifyPassword checking %s with pass %s" % (username, password)
               if self.check(username, password):
                    return True
               return False
          else:
               raise HashStoreException('ERROR: user does not exist')

     def addUser(self, username, password):
          """Adds a user to the hashstore"""
          
          if self.userExist(username):
               raise HashStoreException('ERROR: user already exists')
          self.userDict[username] = self.encode(password)
#          print "foo addUser self.userDict.keys() = %s " % self.userDict.keys()
          self.__saveHashstore()
          return True

     def removeUser(self, username):
          """Removes a given user from the hashstore"""
          
          if self.userExist(username):
               del self.userDict[username]
               self.__saveHashstore()
               return True
          else:
               raise HashStoreException('ERROR: cannot remove user which does not exist')

     def listUsers(self, update=True):
          """Returns the current list of users in the hashstore"""

          if update:
               self.updateUserDict()

#          print "foo listUsers: self.userDict.keys() = %s" % self.userDict.keys()
          return self.userDict.keys()

     def check(self, user, password):
         """Validate password using preset hash function"""
         hash = self.h.copy()
#         print "foo check: user = %s, password = %s" % (user, password)
         hash.update(self.userDict[user.encode('utf-8')].split(':')[0])
         hash.update(password.encode('utf-8'))
         if hash.hexdigest() == self.userDict[user.encode('utf-8')].split(':')[1]:
             return True
         return False

     def encode(self, password):
         """Generate new salt and hash given password using preset hash function"""

         hash = self.h.copy()
         salt = base64.b64encode(self.crypto.get_new_iv())
         hash.update(salt)
         hash.update(password)
         return salt + ':' + hash.hexdigest()

#
# CLI
#
if __name__ == "__main__":

     parser = OptionParser()
     parser.add_option('--configfile', '-f', dest='f', help='Path to config file', action='store')
     parser.add_option('--hashstore', '-s', dest='s', help='Path to hashstore', action='store')
     parser.add_option('--create', '-c', dest='c', help='Create a new hashstore', action='store_true')
     parser.add_option('--list', '-l', dest='l', help='list users in hashstore', action='store_true')
     parser.add_option('--add', '-a',  dest='a', help='add user to hashstore', action='store')
     parser.add_option('--remove', '-r', dest='r', help='remove user from hashstore', action='store')
     parser.add_option('--password', dest='password', help='Ask for password for new hashstore', action='store_true')
     parser.add_option('--random', dest='randomsize', help='Generate random password of specified size', action='store')
     parser.add_option('--version', '-v', dest='v', help='Show program version number', action='store_true')
     (options, args) = parser.parse_args()

     if options.v:
         print 'Version: 1.0'

     if ((options.c and (options.l or options.a or options.r)) or
         (options.l and (options.a or options.r or options.c)) or
         (options.a and (options.r or options.c or options.l)) or
         (options.r and (options.c or options.l or options.a))):
         parser.error("options -c, -l, -a and -r are mutually exclusive.")
         exit(1)

     if options.password and options.random:
         parser.error("options --password and --random are mutually exclusive.")
         exit(2)

     # For creating a new hashstore and configfile
     if options.c:
          datetimeSuffix = datetime.now().strftime("%Y%m%d-%H%M%S")
                    
          if options.password:
               password = getpass.getpass("Please enter hashstore decryption password: ")
               password2 = getpass.getpass("Please repeat hashstore decryption password: ")

               if password != password2:
                    print "ERROR: hashstore not created, passwords do not match"
                    sys.exit(5)
               
               if USECRACKLIB:
                    passwordMessage = safePassword(password)
                    if passwordMessage:
                         print "ERROR: password strength test failed: %s" %passwordMessage
                         sys.exit(-10)
          else:
               if options.randomsize:
                    password = randomPassword(int(options.randomsize))
               else:
                    password = randomPassword(DEFAULTSIZE)
          
          if options.f:
               configFilePath = options.f
          else:
               configFilePath = CONFIGFILE
          
          if options.s:
               hashstorePath = options.s
          else:
               hashstorePath = LOCATION
          
          if os.path.exists(configFilePath):
               os.rename(configFilePath, "%s.%s" % (configFilePath, datetimeSuffix))
          
          if os.path.exists(hashstorePath):
               os.rename(hashstorePath, "%s.%s" % (hashstorePath, datetimeSuffix))
          
          config = RawConfigParser()
          config.add_section('hashstore')
          config.set('hashstore', 'key', "'%s'" % password)
          config.set('hashstore', 'location', os.path.abspath(hashstorePath))
     
          with open(hashstorePath, 'w') as hashstore:
               hashstore.close()
          if os.path.exists(hashstorePath):
               os.chmod(hashstorePath, 0600)
          
          print "Hash store created."
          
          with open(configFilePath, 'w') as configfile:
               config.write(configfile)
          if os.path.exists(configFilePath):
               os.chmod(configFilePath, 0600)
 
          print "Config file created."

          hashStore = HashStore(hashfile=hashstorePath, storeKey=password)
          
          if os.path.exists(hashstorePath):
               print "Hashstore created."
               sys.exit(0)
          else:
               print "ERROR creating hashstore"
               sys.exit(6)
          
     # Will be conducting an operation on a pre-existing hashstore
     else:
          
          # Attempt to use specified hashstore
          if options.s:
               location = options.s
               if not os.path.exists(location):
                    print "ERROR: hashstore does not exist"
                    sys.exit(1)
               password = getpass.getpass("Please enter hashstore decryption password: ")

          # Attempt to use specified configfile
          elif options.f:
               configFilePath = options.f
               config = RawConfigParser()
               config.read(configFilePath)
               password = config.get('hashstore', 'key')
               location = config.get('hashstore', 'location')
          
          # Check if there is a default configfile
          elif os.path.exists(CONFIGFILE):
               configFilePath = CONFIGFILE
               config = RawConfigParser()
               config.read(configFilePath)
               password = config.get('hashstore', 'key')
               location = config.get('hashstore', 'location')
               #try to get info from default configfile
          
          # Check if there is a default hashstore
          elif os.path.exists(LOCATION):
               location = LOCATION
               password = getpass.getpass("Please enter hashstore decryption password: ")
               
          else:
               print "ERROR: hashstore not defined"
               sys.exit(1)
               
          try:
               hashStore = HashStore(hashfile=location, storeKey=password)
          except Exception as e:
               print e
               print "ERROR: could not decrypt hashstore. Is the decryption password correct? Are you trying to open a valid hashstore?"
               sys.exit(2)
               
          if options.l:
               user_list = hashStore.listUsers()
               print "Found %s users." % (len(user_list))
               print "\n".join(user_list)

          elif options.a:
               if hashStore.userExist(options.a):
                    print "ERROR: cannot add user which already exists"
                    sys.exit(2)
               else:
                    userpassword = getpass.getpass("Please enter password for user %s: " % options.a)
                    userpassword2 = getpass.getpass("Please repeat password: ")
                    
                    if userpassword != userpassword2:
                         print "ERROR: did not add user, passwords do not match"
                         sys.exit(3)
                    
                    if USECRACKLIB:
                         passwordMessage = safePassword(userpassword)
                         if passwordMessage:
                              print "ERROR: user password strength test failed --> %s" %passwordMessage
                              sys.exit(-30)
                    
                    hashStore.addUser(options.a, userpassword)

          elif options.r:
               if not hashStore.userExist(options.r):
                    print "ERROR: cannot remove user which does not exist"
               else:
                    hashStore.removeUser(options.r)
                    sys.exit(0)
     
     print "Done!"

