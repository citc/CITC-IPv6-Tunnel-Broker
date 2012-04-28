"""mechanism.py -- SASL mechanism registry

A mechanism is a SASL authentication method.  Mechanisms are
registered with IANA.  This module defines an abstract interface and
registry for mechanisms implemented elsewhere in this package.

Mechanisms may be implemented by subclassing Mechanism or by using the
defined() class decorator.  In either case, the name of the class will
be registered by converting its name into a canonical form.

<http://tools.ietf.org/html/rfc2222>
<http://www.iana.org/assignments/sasl-mechanisms>
"""
from __future__ import absolute_import
import abc, re, collections

__all__ = ('define', 'Mechanism')


### Mechanism

class MechanismType(abc.ABCMeta):
    """This metaclass registers a SASL mechanism when it's defined."""

    def __new__(mcls, name, bases, attr):
        cls = abc.ABCMeta.__new__(mcls, name, bases, attr)
        if cls.__module__ != __name__:
            name = mechanism_name(getattr(cls, '__mechanism__', name))
            cls.__mechanism__ = name
            return register(name, cls)
        return cls

class Mechanism(object):
    """The SASL mechanism interface.  The only two methods required
    are challenge() and respond().  These methods return AuthState
    items.  The continuation field (k) is one of the following:

      callback   call this with data received from the other end
      True       authentication succeeded
      False      authentication failed
      None       need confirmation of success from other end

    A Mechanism can implement any number of steps in an authentication
    sequence by returning callback procedures as the continuation.
    See TestMech.negotiate() in tests.py for an example.
    """

    __metaclass__ = MechanismType
    __slots__ = ()

    SECURE = False

    @abc.abstractmethod
    def challenge(self):
        """Issue a challenge."""

    @abc.abstractmethod
    def respond(self, challenge):
        """Respond to a challenge."""

class AuthState(collections.namedtuple('AuthState', 'k entity data')):

    def __call__(self, response):
        return self.k and self.k(self.entity, response)

    def success(self):
        return self.k is True

    def failure(self):
        return self.k is False

    def confirm(self):
        return self.k is None

    def finished(self):
        return not(callable(self.k))


### Registry

MECHANISMS = {}

def define(name=None):
    """A class decorator that registers a SASL mechanism."""

    def decorator(cls):
        return register(mechanism_name(name or cls), cls)

    return decorator

def register(name, cls):
    """Register a SASL mechanism."""

    MECHANISMS[name] = cls
    return cls

CAMEL = re.compile(r'([a-z0-9_])([A-Z])')
def mechanism_name(obj):
    """
    >>> mechanism_name("FooBar")
    'FOO-BAR'
    >>> mechanism_name('FOO-BAR')
    'FOO-BAR'
    """
    name = getattr(obj, '__name__', None) or str(obj)
    return CAMEL.sub(r'\1-\2', name).strip('_').replace('_', '-').upper()

