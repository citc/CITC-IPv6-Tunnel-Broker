"""rfc -- a parser for RFC grammars

Copyright (c) 2009, Coptix, Inc.  All rights reserved.
See the LICENSE file for license terms and warranty disclaimer.
"""

from __future__ import absolute_import
import re, functools, abc, collections

__all__ = ('ReadError', 'data', 'items', 'sequence', 'quoted')


### Public Interface

class ReadError(Exception): pass

def data(prod, data):
    """Parse data using production and return the unboxed value from
    the result of read()."""

    (result, _) = prod.read(data)
    return result

def items(kind='element_list', default='token_or_quoted_string', rules={}, **kwargs):
    """Parse a sequence of comma-separated key-value pairs.  The type
    of sequence is given by kind.  Each element in the sequence is a
    NAME=VALUE pair where NAME is a token and VALUE is produced by the
    rules parameter.

    >>> prod = items()
    >>> data = { 'foo': 'bar', 'baz': 'frob@mumble.net' }

    >>> written = prod.write(sorted(data.items())); written
    u'baz="frob@mumble.net",foo=bar'

    >>> (read, _) = prod.read(written); read
    [(u'baz', u'frob@mumble.net'), (u'foo', u'bar')]

    >>> prod.read(u'')
    ([], 0)
    >>> prod.write([])
    u''
    """
    return sequence(item(default, rules), kind, **kwargs)

def sequence(element='token_or_quoted_string', kind='element_list', **kwargs):
    """A sequence of comma-separated elements."""

    return production(kind, element, **kwargs)

def quoted(kind=None):
    """Parse a quoted element.

    >>> prod = quoted()
    >>> written = prod.write(['a', 'b', 'c']); written
    u'"a,b,c"'
    >>> (read, _) = prod.read(written); read
    [u'a', u'b', u'c']
    """
    return quote(kind)


### Production

class BadToken(ReadError): pass

PRODUCTIONS = {}

def register_production(cls):
    PRODUCTIONS[cls.__name__] = cls
    return cls

def production(name, *args, **kwargs):
    """Look up a production by name."""

    result = name if is_production(name) else PRODUCTIONS.get(name)
    if isinstance(result, type) and issubclass(result, Parameterized):
        return result(*args, **kwargs)
    return result

def is_production(obj):
    """Return True if obj is a Production."""

    return (
        (isinstance(obj, type) and issubclass(obj, Production))
        or isinstance(obj, Production)
    )

class ProductionType(abc.ABCMeta):
    """Register a production when it is declared."""

    def __new__(mcls, name, bases, attr):
        cls = abc.ABCMeta.__new__(mcls, name, bases, attr)
        return register_production(cls)

class Production(object):
    """A production in a grammar that may be used to read data from a
    string or write data to a string.  The read() and write() methods
    should be implemented so that the following is true:

    prod.read(prod.write(value)) == value
    """

    __metaclass__ = ProductionType
    __slots__ = ()

    @abc.abstractmethod
    def read(cls, data, pos=0):
        """Produce a (value, new-pos) item by reading from data
        beginning at pos.  If the value cannot be produced, return
        (None, pos)."""

    @abc.abstractmethod
    def write(cls, data):
        """Return a unicode value that can be written to a stream by
        using data."""

class Parameterized(Production):
    """A Production that can be parameterized by making an instance.
    Initializers should declare default values for all parameters if
    possible."""

    @abc.abstractmethod
    def __init__(self):
        pass

def regular(pattern):
    """Use a regular expression to drive a read() method."""

    PATTERN = re.compile(pattern)
    def decorator(proc):

        @classmethod
        @functools.wraps(proc)
        def internal(cls, data, pos=0):
            probe = PATTERN.match(data, pos)
            value = probe and proc(cls, probe)
            if value is None:
                return (value, pos)
            return (value, pos + len(probe.group(0)))

        return internal
    return decorator

def require(prod, data, pos):
    """Require a production to succeed.  If it fails, raise a BadToken
    exception."""

    result = prod.read(data, pos)
    if result[0] is None:
        raise BadToken(prod, data, pos)
    return result


### Parameterized Productions

class element_list(Parameterized):
    """A list of elements separated by commas.  Look for the
    definition of '#rule' in the grammar at the end of the DIGEST-MD5
    spec (end of page 21)."""

    def __init__(self, element=None, min=None, max=None):
        self.element = production(element)
        self.min = min
        self.max = max

    def read(self, data, pos=0):
        """Parse data that looks like:

          ( *LWS element *( *LWS "," *LWS element ))
        """
        elem = self.element.read
        result = []

        (_, new_pos) = LWS.read(data, pos)
        while self.max is None or len(result) < self.max:
            (value, new_pos) = elem(data, new_pos)
            if value is None:
                if result:
                    ## A comma was followed by something that is not
                    ## an element.
                    raise BadToken(elem, data, new_pos)
                break
            else:
                result.append(value)

            ## Stop if there isn't a trailing comma.
            (_, new_pos) = LWS.read(data, new_pos)
            (_, new_pos) = COMMA_LWS.read(data, new_pos)
            if _ is None:
                break

        if self.min is not None and len(result) < self.min:
            raise BadToken(self, data, pos)

        return (result, new_pos)

    def write(self, data):
        elem = self.element.write
        if isinstance(data, collections.Mapping):
            data = data.iteritems()
        return COMMA_LWS.write(None).join(
            elem(value) for value in data
        )

class item(Parameterized):
    """Parse a sequence of headers.  The type of sequence is given by
    kind.  Each element in the sequence is a name=value item where
    name is a token and value is produced by the rules parameter.

    >>> prod = item()
    >>> prod.write(('foo', 'bar'))
    u'foo=bar'
    >>> prod.read(u'foo="baz@mumble.net"')
    ((u'foo', u'baz@mumble.net'), 20)
    """

    QUOTES = True

    def __init__(self, default='token_or_quoted_string', rules={}):
        self.default = default and production(default)
        self.grammar = dict(
            (k, maybe_unquote(production(v)))
            for (k, v) in rules.iteritems()
        )

    def production(self, name):
        """Find the production for a value based on an item's name.
        If no rule is found, try to fall back on a default rule."""

        result = self.grammar.get(name) or self.default
        if not result:
            raise ReadError('Unrecognized rule %r.' % name)
        return result

    def read(self, data, pos=0):
        try:
            (name, new_pos) = require(token, data, pos)
            (_, new_pos) = require(equals, data, new_pos)
            (value, new_pos) = require(self.production(name), data, new_pos)
            return ((name, value), new_pos)
        except BadToken:
            return (None, pos)

    def write(self, data):
        (name, value) = data
        return equals.write(None).join((
            token.write(name),
            self.production(name).write(value)
        ))

class quote(Parameterized):
    QUOTES = True

    def __init__(self, kind=None):
        self.kind = production(kind) if kind else element_list(token, min=1)

    def read(self, data, pos=0):
        try:
            (_, new_pos) = require(double_quote, data, pos)
            (value, new_pos) = require(self.kind, data, new_pos)
            (_, new_pos) = require(double_quote, data, new_pos)
            return (value, new_pos)
        except BadToken:
            return (None, pos)

    def write(self, data):
        dq = double_quote.write(None)
        return u'%s%s%s' % (dq, self.kind.write(data), dq)

class MaybeUnquote(Parameterized):
    def __init__(self, kind):
        self.kind = kind
        self.write = kind.write

    def read(self, data, pos=0):
        try:
            if data[pos] != '"':
                return self.kind.read(data, pos)
        except IndexError:
            raise BadToken(self, data, pos)

        try:
            (quoted, new_pos) = require(quoted_string, data, pos)
            (value, val_pos) = require(self.kind, quoted, 0)
            if val_pos == len(quoted):
                return (value, new_pos)
            return (None, pos)
        except BadToken:
            return (None, pos)

    def write(self, data):
        return self.kind.write(data)

def maybe_unquote(prod):
    """
    >>> int = maybe_unquote(integer)
    >>> int.read('123')
    (123, 3)
    >>> int.read("123")
    (123, 3)
    >>> int.read("foo")
    (None, 0)
    """
    prod = production(prod)
    return prod if getattr(prod, 'QUOTES', False) else MaybeUnquote(prod)


### Simple Productions

class token_or_quoted_string(Production):
    """
    >>> token_or_quoted_string.read('foo')
    ('foo', 3)
    >>> token_or_quoted_string.read('"frob",')
    ('frob', 6)

    >>> token_or_quoted_string.write('foo')
    u'foo'
    >>> token_or_quoted_string.write('frob@mumble.net')
    u'"frob@mumble.net"'
    """

    QUOTES = True
    SEPARATOR = re.compile(r'[\(\)<>@,;:\\"/\[\]\?={}\s]')

    @classmethod
    def read(cls, data, pos=0):
        try:
            return (quoted_string if data[pos] == '"' else token).read(data, pos)
        except IndexError:
            return None

    @classmethod
    def write(cls, data):
        if cls.SEPARATOR.search(data):
            return quoted_string.write(data)
        else:
            return token.write(data)

class quoted_string(Production):
    """A quoted string is delimited by double quotes.  Individual
    characters may be escaped with a backslash.

    >>> quoted_string.read('foo="mumble \\\\"frob\\\\""', 4)
    ('mumble "frob"', 21)
    >>> quoted_string.read('foo=bar')
    (None, 0)
    """

    QUOTES = True
    UNESCAPE = re.compile(r'\\(.)')

    @regular(r'"((?:\\.|[^"])+)"')
    def read(cls, match):
        return cls.UNESCAPE.sub(r'\1', match.group(1))

    @classmethod
    def write(cls, data):
        return u'"%s"' % data.replace('"', '\\"')

class token(Production):
    """A token is a sequence of non-separator characters.

    >>> token.read('frob-mumble,')
    ('frob-mumble', 11)
    """

    @regular(r'[^\(\)<>@,;:\\"/\[\]\?={}\s}>]+')
    def read(cls, match):
        return match.group(0)

    @classmethod
    def write(cls, data):
        return unicode(data)

class integer(Production):
    """An integer is a sequence of digits.

    >>> integer.read('123,')
    (123, 3)
    """

    @regular(r'\d+')
    def read(cls, match):
        try:
            return int(match.group(0))
        except ValueError:
            return None

    @classmethod
    def write(cls, data):
        return unicode(data)

class hexidecimal(Production):
    """An integer as a hexidecimal value. """

    @regular(r'[\da-f]+')
    def read(cls, match):
        try:
            return int(match.group(0), 16)
        except ValueError:
            return None

    @classmethod
    def write(cls, data):
        ## Strip off the '0x' prefix.
        return unicode(hex(data)[2:])

class equals(Production):

    @regular(r'=')
    def read(cls, match):
        return match.group(0)

    @classmethod
    def write(cls, data):
        return u'='

class double_quote(Production):

    @regular(r'"')
    def read(cls, match):
        return match.group(0)

    @classmethod
    def write(cls, data):
        return u'"'

class LWS(Production):
    """Linear white space."""

    @regular('(?:\r\n)?[ \t]+')
    def read(cls, match):
        return match.group(0)

    @classmethod
    def write(cls, data):
        return u' '

class COMMA_LWS(Production):
    """A comma with optional linear whitespace on either side.  Many
    commas in a row count as one comma."""

    @regular('(?:,(?:\r\n)?[ \t]*)+')
    def read(cls, match):
        return match.group(0)

    @classmethod
    def write(cls, data):
        return u','
