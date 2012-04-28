"""digest_md5.py -- DIGEST-MD5 SASL mechanism

<http://www.ietf.org/rfc/rfc2831.txt>

Copyright (c) 2009, Coptix, Inc.  All rights reserved.
See the LICENSE file for license terms and warranty disclaimer.
"""

from __future__ import absolute_import
import re, functools, random, struct, base64, hashlib, binascii
from . import mechanism as mech, rfc, auth, log

__all__ = ('DigestMD5', 'DigestMD5Password')

class DigestMD5(mech.Mechanism):

    SECURE = True

    def __init__(self, auth):
        self.auth = auth

    state = mech.AuthState

    ## Server
    ## 1. Issue challenge.
    ## 2. Verify challenge response is correct; reply with rspauth.
    ## 3. Wait for client to acknowledge rspauth.

    def challenge(self):
        ## Issue a challenge; continue by verifying the client's
        ## response.
        return self.state(self.verify, None, self.write(self.CHALLENGE, {
            'realm': self.auth.realm(),
            'nonce': self.make_nonce(),
	    'qop': ['auth'],
	    #'qop': '"auth"',
            'charset': 'utf-8',
            'algorithm': 'md5-sess'
        }))

    def verify(self, entity, data):
        try:
            response = dict(rfc.data(self.RESPOND, data))
        except rfc.ReadError as exc:
            log.error('ReadError: %r', exc)
            return self.state(False, entity, None)

        ## If the nonce count is not one, the client is trying to use
        ## "subsequent authentication", but this is usupported.
        if response.get('nc') != 1:
            log.error('nc = %r; expected 1', response.get('nc'))
            return self.state(False, entity, '')

        ## Confirm the digest-uri.
        if not self.verify_digest_uri(response.get('digest-uri')):
            log.error(
                'digest-uri = %r; expected %r',
                response.get('digest-uri'),
                self.make_digest_uri()
            )
            return self.state(False, entity, '')

        ## Make sure the username exists, get the stored password.
        entity = response.get('username')
        passwd = entity and self.auth.get_password(entity)
        if not passwd:
            log.error('Missing entity (%r) or password (%r)', entity, passwd)
            return self.state(False, entity, '')

        ## The password must be stored in a format compatible with
        ## DigestMD5Password.  Convert it to a binary representation
        ## and generate the response hashes.
        try:
            uh = DigestMD5Password.digest(self.auth, entity, passwd)
            (expect, rspauth) = self.make_response(response, uh)
        except auth.PasswordError as exc:
            log.error('PasswordError: %r' % exc)
            return self.state(False, entity, '')

        ## Verify that the response hashes match.
        if expect != response.get('response'):
            log.error(
                'expected response=%r, got %r',
                expect,
                response.get('response')
            )
            return self.state(False, entity, '')

        ## Return the rspauth hash; wait for acknowledgement.
        return self.state(self.finish, entity, self.write(self.VERIFY, {
            'rspauth': rspauth
        }))

    def finish(self, entity, data):
        ## The client has acknowledges the rspauth sent;
        ## authentication was successful.
        return self.state(True, entity, '')

    ## Client
    ## 1. Respond to server challenge.
    ## 2. Wait for rspauth; verify it.
    ## 3. Reply with an empty acknowledgement to confirm.

    def respond(self, data):
        try:
            challenge = dict(rfc.data(self.CHALLENGE, data))
        except rfc.ReadError:
            return self.state(False, None, None)

        enc = self.encoding(challenge)
        zid = self.auth.authorization_id()
        cid = unicode(self.auth.username()).encode(enc)

        ## Derive response parameters from the challenge and from the
        ## client environment.
        params = {
            'username': cid,
            'realm': challenge.get('realm', u''),
            'nonce': challenge['nonce'],
            'cnonce': self.make_nonce(),
            'nc': 1,
            'digest-uri': self.make_digest_uri(),
            'charset': ('charset' in challenge and enc),
            'authzid': (zid and zid.encode('utf-8'))
        }

        ## Generate hashes.  The `expect' hash will be compared to the
        ## rspauth from the server later.
        (rsp, expect) = self.make_response(params)
        params['response'] = rsp

        ## Generate the response; continue by acknowledging the
        ## server's response.
        ack = lambda *a: self.acknowledge(expect, *a)
        return self.state(ack, zid or cid, self.write(self.RESPOND, params))

    def acknowledge(self, expect, entity, data):
        try:
            verify = dict(rfc.data(self.VERIFY, data))
        except rfc.ReadError:
            return self.state(False, entity, None)

        ## If the rspauth matches the expected value, authentication
        ## was successful.  The server expects an empty reply that
        ## confirms acknowledgement.
        if verify.get('rspauth') == expect:
            return self.state(self.accepted, entity, '')
        log.error('expected rspauth=%r, got %r', expect, verify.get('rspauth'))
        return self.state(False, entity, None)

    def accepted(self, entity, data):
        assert data == ''
        return self.state(True, entity, None)

    ## Grammars

    CHALLENGE = rfc.items(min=1, rules={
        'realm': 'quoted_string',
        'nonce': 'quoted_string',
        'qop': rfc.quoted(rfc.sequence('token')),
	#'qop': 'token',
        'stale': 'token',
        'maxbuf': 'integer',
        'charset': 'token',
        'algorithm': 'token',
        'cipher': rfc.quoted(rfc.sequence('token'))
    })

    RESPOND = rfc.items(min=1, rules={
        'username': 'quoted_string',
        'nonce': 'quoted_string',
        'cnonce': 'quoted_string',
        'nc': 'hexidecimal',
        'qop': 'token',
        'digest-uri': 'quoted_string',
        'response': 'token',
        'maxbuf': 'integer',
        'cipher': 'token',
        'authzid': 'quoted_string',
    })

    VERIFY = rfc.items(min=1, rules={
        'rspauth': 'token'
    })

    ## Aux

    def write(self, production, values):
        return production.write(i for i in values.iteritems() if i[1])

    def encoding(self, values):
        return values.get('charset', 'iso-8859-1')

    def qop(self, values):
        return values.get('qop', 'auth')

    def make_nonce(self):
        random.seed()
        value = random.getrandbits(64)
        return base64.b64encode(''.join(struct.pack('L', 0xFFFFFFFF & value)))

    def make_digest_uri(self):
        auth = self.auth
        service = auth.service_name()
        return '%s/%s%s' % (
            auth.service_type(),
            auth.host(),
            ('/%s' % service if service else u'')
        )

    DIGEST_URI = re.compile('^([^/]+)/([^/]+)(?:/(.+))?$')

    def verify_digest_uri(self, uri):
        probe = uri and self.DIGEST_URI.match(uri)
        if not probe:
            return False
        auth = self.auth
        service = auth.service_name()
        (A, B, C) = probe.groups()
        return (
            A == auth.service_type()
            and (B == auth.host() or B == auth.realm())
            and (not service or C == service)
        )

    def make_response(self, data, uh=None, kinds=('AUTHENTICATE', '')):
        enc = self.encoding(data)
        user = data['username']

        uh = uh or user_hash(user, data['realm'], self.auth.password(), enc).digest()
        a1 = a1_hash(uh, data['nonce'], data['cnonce'], data.get('authzid'))

        result = []
        for kind in kinds:
            a2 = a2_hash(self.qop(data), kind, data['digest-uri'])
            rsp = response_hash(a1, a2, data['nonce'], data['nc'], data['cnonce'], self.qop(data))
            result.append(rsp.hexdigest())

        return result

class DigestMD5Password(auth.PasswordType):
    """A DIGEST-MD5 password is stored as the hexidecimal
    representation of the user_hash().  This depends on the username,
    realm, and password."""

    @staticmethod
    def make(authenticator, user, passwd):
        KIND = 'DIGEST-MD5'

        ## Check to see if a hash object has been passed in.
        if callable(getattr(passwd, 'hexdigest', None)):
            return auth.make_password(KIND, passwd.hexdigest())

        (kind, secret) = auth.password_type(passwd)
        if kind == KIND:
            return passwd
        elif kind is None or kind == 'PLAIN':
            uh = user_hash(user, authenticator.realm(), passwd)
            return auth.make_password(KIND, uh.hexdigest())
        raise auth.PasswordError('Expected %s or PLAIN, not %s' % (KIND, kind))

    @classmethod
    def digest(cls, authenticator, user, passwd):
        (_, secret) = auth.password_type(cls.make(authenticator, user, passwd))
        return binascii.a2b_hex(secret)


### Hashing

def response_hash(a1, a2, nonce, nc, cnonce, qop):
    """Final response hash (see RFC-2831 page 10)."""

    return colons(
        md5, a1.hexdigest(),
        nonce, '%08x' % nc,
        cnonce, qop, a2.hexdigest()
    )

def user_hash(user, realm, passwd, encoding='utf-8'):
    """User hash, specified as part of A1 in RFC-2831, but implemented
    independently so passwords can be hashed and stored."""

    if encoding == 'utf-8':
        user = iso_8859_1(user)
        realm = iso_8859_1(realm)
        passwd = iso_8859_1(passwd)

    return colons(md5, user, realm, passwd)

def a1_hash(uh, nonce, cnonce, authzid):
    """A1 hash (see RFC-2831 page 10).  The uh parameter is the result
    of user_hash()."""

    return colons(md5, uh, nonce, cnonce, authzid)

def a2_hash(qop, kind, digest_uri):
    """A2 hash (see RFC-2831 page 10)."""

    return colons(md5, kind, digest_uri, '' if qop == 'auth' else ('0' * 32))

def iso_8859_1(value):
    """Try to downgrade a unicode value to ISO-8859-1 for
    compatibility with HTTP/1.0."""

    try:
        if isinstance(value, unicode):
            return value.encode('iso-8859-1')
    except UnicodeEncodeError:
        value = value.encode('utf-8')
    return value

def md5(v1, *values):
    """Create a hash over a sequence of values."""

    result = hashlib.md5(v1)
    for value in values:
        result.update(value)
    return result

def colons(make, v1, *values):
    """Create a hash over a sequence of values.  Colons are
    interspersed between sequence elements."""

    result = make(v1)
    for value in values:
        if value:
            result.update(':')
            result.update(value)
    return result
