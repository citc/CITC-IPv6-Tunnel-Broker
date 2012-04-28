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

from formencode import Schema, validators, FancyValidator
import formencode
import crack

import bjsonrpc
from ddtbmanage.config  import DDTBManageConfig
from ddtbmanage.address import IPv4Address, IPv6Address
from hashstore.hashstoremanager import *

config = DDTBManageConfig()

#
# Custom Validator Classes
#

#class SameAsOldPasswrd(FormValidator):
#    """
#    Tests to see if new password is the same as the old
#    """
#
#    show_match = False
#    field_names = None
#    validate_partial_form = True
#
#    __unpackargs__ = ('*', 'field_names')
#
#    messages = dict(
#        invalid=_('Password Fields do not match (should be %(match)s)'),
#        invalidNoMatch=_('Fields do not match'),
#        notDict=_('Fields should be a dictionary'))
#
#    def __init__(self, *args, **kw):
#        super(FieldsMatch, self).__init__(*args, **kw)
#        if len(self.field_names) < 2:
#            raise TypeError('FieldsMatch() requires at least two field names')
#
#    def validate_partial(self, field_dict, state):
#        for name in self.field_names:
#            if name not in field_dict:
#                return
#        self.validate_python(field_dict, state)
#
#    def validate_python(self, field_dict, state):
#        try:
#            ref = field_dict[self.field_names[0]]
#        except TypeError:
#            # Generally because field_dict isn't a dict
#            raise Invalid(self.message('notDict', state), field_dict, state)
#        except KeyError:
#            ref = ''
#        errors = {}
#        for name in self.field_names[1:]:
#            if field_dict.get(name, '') != ref:
#                if self.show_match:
#                    errors[name] = self.message('invalid', state,
#                                                match=ref)
#                else:
#                    errors[name] = self.message('invalidNoMatch', state)
#        if errors:
#            error_list = errors.items()
#            error_list.sort()
#            error_message = '<br>\n'.join(
#                ['%s: %s' % (name, value) for name, value in error_list])
#            raise Invalid(error_message, field_dict, state, error_dict=errors)




class UniqueUsername(FancyValidator):
     def _to_python(self, value, state):
        rpc = bjsonrpc.connect(host=config.ipc.rpcip, port=int(config.ipc.port))
        hashStore = HashStore()
        
        try:
            usernames = rpc.call.listUsers(config.ipc.apikey)
            rpc.close()
            usernames.append(hashStore.listUsers())
            
        except Exception,e:
            raise formencode.Invalid('Cannot get pre-existing user list, contact administrator', value, state)
        if value in usernames:
             raise formencode.Invalid(
                'Username with specified login already exists',
                value, state)
        return value

class ValidUser(FancyValidator):
     def _to_python(self, value, state):
        rpc = bjsonrpc.connect(host=config.ipc.rpcip, port=int(config.ipc.port))
        try:
            usernames = rpc.call.listUsers(config.ipc.apikey)
            rpc.close()

        except Exception,e:
            raise formencode.Invalid('Cannot get pre-existing user list, contact administrator', value, state)
        if not value in usernames:
             raise formencode.Invalid(
                'Username with specified login does not exist',
                value, state)
        return value

class ValidIPAddress(FancyValidator):
     def _to_python(self, value, state):
        try:
            IPv4Address(value).ipaddress
        except ValueError:
            try:
                IPv6Address(value).ipaddress
            except ValueError:
                raise formencode.Invalid('Invalid IP address', value, state)
        return value

# Note: from our form, the password comes as utf-8, but it is 'wrong'
# utf for crack.VeryFascistCheck. Using value.encode fixes this

class ClientPassword(FancyValidator):
     def _to_python(self, value, state):
        try:
            crack.VeryFascistCheck(value.encode('utf-8'))
        except ValueError, e:
            raise formencode.Invalid("New password " + str(e), value, state)
        return value

#
#  Forms
#

class LoginForm(Schema):
#    captcha = validators.UnicodeString(not_empty=True)
#    user = formencode.All(validators.PlainText(not_empty=True), validators.MaxLength(30))
    user = formencode.All(validators.UnicodeString(not_empty=True), validators.MaxLength(30))
    passwd = formencode.All(validators.UnicodeString(not_empty=True), validators.MaxLength(253))

class ClientPasswordChangeForm(Schema):
    oldPassword = formencode.All(validators.UnicodeString(not_empty=True), validators.MaxLength(253))
#    newPassword = formencode.All(ClientPassword(not_empty=True), validators.MaxLength(253))
    newPassword = formencode.All(validators.UnicodeString(not_empty=True), validators.MaxLength(253))
    newPasswdConfirm = formencode.All(validators.UnicodeString(not_empty=True), validators.MaxLength(253))
    chained_validators = [validators.FieldsMatch('newPassword', 'newPasswdConfirm')]

class ClientAddForm(Schema):
    login = formencode.All(validators.UnicodeString(not_empty=True), UniqueUsername())
    name = validators.String(not_empty=True)
    email = validators.Email(not_empty=True)
    mobile = validators.Regex(r'^[+]?[\d\ \-]{6,15}$')(not_empty=True)
