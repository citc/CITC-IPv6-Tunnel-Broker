"""auth -- rudimentary authenticator interface

This authenticator interface wraps up the messy loose-ends of
interfacing SASL to a real environment.

Copyright (c) 2009, Coptix, Inc.  All rights reserved.
See the LICENSE file for license terms and warranty disclaimer.
"""

from __future__ import absolute_import
import abc, re

__all__ = (
    'Authenticator', 'SimpleAuth',
    'PasswordType', 'PasswordError', 'password_type', 'make_password'
)

### Authenticator

class Authenticator(object):
    """A basic authentication interface used by SASL mechanisms."""

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def service_type(self):
        """The type of service for which authentication is being
        requested."""

    @abc.abstractmethod
    def host(self):
        """The host name of the service for which authentication is
        being requested."""

    def realm(self):
        """The authentication realm."""
        return u'%s@%s' % (self.service_name() or self.service_type(), self.host())

    def service_name(self):
        """The name of the service for which authentication is being
        requested."""
        return u''

    @abc.abstractmethod
    def username(self):
        """Identify the entity being authenticated (e.g. username)."""

    @abc.abstractmethod
    def password(self):
        """The password associated with the username."""

    @abc.abstractmethod
    def get_password(self, user):
        """Return the password associated with user."""

    def authorization_id(self):
        """Identify the effective entity if authentication
        succeeds."""
        return u''

    def verify_password(self, authorize, user, passwd):
        """Verify that the user's password matches and that this user
        is authorized to act on behalf of authorize."""

        probe = self.get_password(user)
        return (
            probe is not None
            and self._compare_passwords(user, passwd, probe)
            and self._verify_authorization(user, authorize)
        )

    def _compare_passwords(self, user, attempt, stored):
        """Return True if the attempt matches the stored password for
        user."""

        return attempt == stored

    def _verify_authorization(self, user, authorize):
        """Verify that user has authorization to act as authorize."""
        return not authorize or user == authorize

class SimpleAuth(Authenticator):
    """Authenticate from a Mapping."""

    def __init__(self, pass_type, users, user, passwd, serv_type, host, authzid=None, realm=None):
        self._pass_type = pass_type
        self._user = user
        self._passwd = passwd
        self._authzid = authzid
        self._serv_type = serv_type
        self._host = host

        if realm:
            self.realm = realm

        ## Install
        self._entities = dict(
            (k, pass_type.make(self, k, p))
            for (k, p) in users.iteritems()
        )

    def username(self):
        value = self._user()
        if not value:
            raise RuntimeError('Undefined authentication entity.')
        return value

    def password(self):
        return self._passwd()

    def authorization_id(self):
        return self._authzid and self._authzid()

    def get_password(self, user):
        return self._entities.get(user)

    def service_type(self):
        return self._serv_type()

    def host(self):
        return self._host()

    def _compare_passwords(self, user, attempt, stored):
        try:
            return self._pass_type.make(self, user, attempt) == stored
        except PasswordError:
            return False

### Passwords

## Passwords are formatted as "{TYPE}secret".

TYPE = re.compile('^(?:{([^}]+)})?(.*)$')

def password_type(passwd):
    if not isinstance(passwd, basestring):
        return (None, passwd)
    probe = TYPE.match(passwd)
    return probe.groups() if probe else (None, passwd)

def is_type(passwd, kind):
    return password_type(passwd)[0] == kind

def is_untyped(passwd):
    return is_type(passwd, None)

def make_password(kind, passwd):
    return u'{%s}%s' % (kind, passwd)

class PasswordError(Exception): pass

class PasswordType(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def make(auth, user, passwd):
        """Make a password for user or raise a PasswordError."""
        return passwd
