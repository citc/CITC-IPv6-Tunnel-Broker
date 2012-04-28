"""tests -- unit tests

Copyright (c) 2009, Coptix, Inc.  All rights reserved.
See the LICENSE file for license terms and warranty disclaimer.
"""

from __future__ import absolute_import
import unittest
from md import fluid
from . import *

## Fluid parameters representing configuration values or request
## parameters.
USER = fluid.cell()
PASS = fluid.cell()
SERV = fluid.cell('test-service')
HOST = fluid.cell('example.net')

## User database and authentication.
USERS = { 'foo@bar.com': 'baz' }

AUTH = SimpleAuth(
    DigestMD5Password, USERS, USER.get, PASS.get, SERV.get, HOST.get
)

class TestRFC(unittest.TestCase):
    """Test the RFC parser."""

    def setUp(self):
        from . import rfc

        self.headers = rfc.items(min=1, rules={
            'maxbuf': 'integer',
            'qop': rfc.quoted()
        })

    def test_write(self):
        data = self.headers.write(sorted({
            'foo': 'bar',
            'baz': 'mumble "quux" frob!',
            'qop': ['auth', 'auth-conf'],
            'maxbuf': 1024
        }.items()))

        self.assertEqual(
            data,
            u'baz="mumble \\"quux\\" frob!",foo=bar,maxbuf=1024,qop="auth,auth-conf"'
        )

    def test_read(self):
        data = u'baz="mumble \\"quux\\" frob!",foo=bar,maxbuf=1024,qop="auth,auth-conf"'
        (value, _) = self.headers.read(data)
        self.assertEqual(value, [
            (u'baz', u'mumble "quux" frob!'),
            (u'foo', u'bar'),
            (u'maxbuf', 1024),
            (u'qop', [u'auth', u'auth-conf'])
        ])

    def test_read_null(self):
        (value, _) = self.headers.read(u'a=b , , c=d')
        self.assertEqual(value, [('a', 'b'), ('c', 'd')])

    def test_read_incomplete(self):
        from . import rfc

        self.assertRaises(
            rfc.ReadError,
            lambda: self.headers.read(u'maxbuf=')
        )

class TestMech(object):
    """A suite of tests that can be run against any Mechanism.
    Subclass this mixin and declare MECH to be a Mechanism."""

    MECH = None

    def setUp(self):
        import logging
        self.mech = self.MECH(AUTH)
        log.setLevel(logging.CRITICAL)

    def test_success(self):
        (sk, ck) = self.negotiate('foo@bar.com', 'baz')
        self.assert_(self.coalesce(sk, ck))
        self.assert_(self.coalesce(ck, sk))

    def test_failure(self):
        (sk, ck) = self.negotiate('foo@bar.com', 'mumble')
        self.assertFalse(self.coalesce(sk, ck))

    def coalesce(self, value, default):
        return default.success() if value.confirm() else value.success()

    def negotiate(self, user, passwd):
        """Normally this negotiation would take place over a network.
        The `sdata' and `cdata' variables are the data that could be
        sent from the server and from the client.  The `sk' and `ck'
        variables represent the "continuation" of the server and
        client.

        A continuation is a procedure if the exchange should continue,
        False if authentication failed, or True if authentication
        succeeded, or None if the decision is left up to the other end
        of the exchange."""

        ## Server issues a challenge.
        sk = self.mech.challenge()

        ## Client responds.
        with fluid.let((USER, user), (PASS, passwd)):
            ck = self.mech.respond(sk.data)

        while not (sk.finished() and ck.finished()):
            if not sk.finished():
                sk = sk(ck.data)

            if not ck.finished():
                ck = ck(sk.data)

        return (sk, ck)

class TestPlain(TestMech, unittest.TestCase):
    MECH = Plain

class TestDigestMD5(TestMech, unittest.TestCase):
    MECH = DigestMD5

    def test_challenge(self):
        """Test basic expectations about a challenge."""

        state = self.mech.challenge()
        challenge = dict(rfc.data(self.mech.CHALLENGE, state.data))

        ## Nonce is random, so it can't be compared for equality.
        self.assert_(challenge.pop('nonce'))

        self.assertEqual(sorted(challenge.items()), [
            ('algorithm', 'md5-sess'),
            ('charset', 'utf-8'),
            ('realm', 'test-service@example.net')
        ])

    def test_response(self):
        """Test basic expectations about a response."""

        state = self.mech.challenge()
        with fluid.let((USER, 'user@example.net'), (PASS, 'secret')):
            rstate = self.mech.respond(state.data)
            resp = dict(rfc.data(self.mech.RESPOND, rstate.data))

        self.assertNotEqual(resp['nonce'], resp['cnonce'])

        ## These are random, so pop them off before equality
        ## comparison.
        self.assert_(resp.pop('nonce'))
        self.assert_(resp.pop('cnonce'))
        self.assert_(resp.pop('response'))

        self.assertEqual(sorted(resp.items()), [
            (u'charset', u'utf-8'),
            (u'digest-uri', u'test-service/example.net'),
            (u'nc', 1),
            (u'realm', u'test-service@example.net'),
            (u'username', u'user@example.net')
        ])

    def test_nonce(self):
        """Test that the nonce is random."""

        self.assertNotEqual(
            self.mech.make_nonce(),
            self.mech.make_nonce()
        )

