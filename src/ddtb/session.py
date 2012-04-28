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
DDTB tunnel broker client sessions implementation
"""

import os,sys,re,time,datetime,struct,base64
import socket,select,signal
import collections
import time
from xml.parsers.expat import ExpatError
from xml.dom.minidom import parseString

from ddtb           import DDTBError
from ddtb.config    import DDTBConfig
from ddtb.database  import DDTBDatabase
from ddtb.tunnel    import TSPTunnelConfig,TSPTunnelConfigManager
from ddtb.auth      import DDTBLoadAuthenticator
from ddtb.prefix    import CustomerAllocation,CustomerAddressPool
from ddtb.ipc       import TBRPCServer, isActive
from ddtb.crypto    import TBCrypt

# Poller timeout in milliseconds
POLLER_TIMEOUT = 60000
POLL_READ_ONLY = select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR
POLL_READ_WRITE = POLL_READ_ONLY | select.POLLOUT

# All valid actions: we don't implement all of them yet!
TSP_VALID_ACTIONS = ['create','delete','info','accept','reject']

TUNNEL_INFO_XML_REPLY = \
"""<tunnel action="info" type="%(tunnel_type)s" lifetime="1440">
 <server>
  <address type="ipv4">%(server_ipv4)s</address>
  <address type="ipv6">%(server_ipv6)s</address>
 </server>
 <client>
  <address type="ipv4">%(client_ipv4)s</address>
  <address type="ipv6">%(client_ipv6)s</address>%(keepalive)s
  <router>
    <prefix length="%(prefix_mask)s">%(server_ipv6)s</prefix>
  </router>
 </client>
</tunnel>
"""

TUNNEL_KEEPALIVE_XML_REPLY = \
"""<keepalive interval="%(keepalive)d">
  <address type="ipv6">%(server_ipv6)s</address>
</keepalive>"""

TUNNEL_CAPABILITIES = 'CAPABILITY %s' % ' '.join([
    'TUNNEL=V6UDPV4', 'AUTH=DIGEST-MD5',
])

# You could add AUTH=PLAIN, AUTH=ANONYMOUS to the list

TUNNEL_SUPPORTED_TYPES = ['v6udpv4','v6anyv4']
TUNNEL_SUPPORTED_VERSIONS = ['2.0.0','2.0.1','2.0.2']

# Tunnel response codes in standard format
OK = '200 Success'
AUTHFAIL = '300 Authentication Failed'
UNSUPPORTED_VERSION = '302 Unsupported client version'
UNSUPPORTED_TUNNELTYPE = '303 Unsupported tunnel type: The server does not provide the requested tunnel type.'
INVALID_REQUEST = '500 Invalid request format or specified length: The received request has invalid syntax or is truncated.'
NEGOTIATION_TIMEOUT = '599 Negotiation timeout exceeded. It is set here to 30 seconds, please hurry up.'
SERVER_ERROR = '310 Server side error:  Undefined server error.'
# Wrapper for message codes to be sent
def response_code(code):
    if code is not OK:
        logs.session.debug('RESPONSE: %s' % code)
    if type(code) != str:
        raise DDTBError('Unknown response code: %s' % code)
    return '%s\r\n' % code

class ShutDownException(Exception):
    def __str__(self):
        return self.args[0]

class ReconfigureException(Exception):
    def __str__(self):
        return self.args[0]

def DDTBSignalHandler(signum, frame):
    """
    Handler for various OS signals
    """
    #logs.ddtb.debug('Received signal: %s' % signum)
    if signum == signal.SIGINT:
        raise ShutDownException('Received SIGINT')
    if signum == signal.SIGTERM:
        raise ShutDownException('Received SIGTERM')
    if signum in [signal.SIGHUP]:
        raise ReconfigureException('Received SIGHUP')

class CustomerSession(dict):
    """
    Customer tunnel child process
    """
    def __init__(self, manager, session_key, server_ipv4, remote_address):
        """
        Initialize customer tunnel state to unconnected client
        """
        self.manager = manager

        self.server_ipv4 = server_ipv4
        self.remote_address = remote_address
        self.session_key = session_key
        self.state = 'init'

        self.seq = 0
        self.wfd = None
        self.rfd = None

        self.tunnel_type = 'UNDEFINED'
        self.NAT = False
        self.client_id = None
        self.iters = 0

    def init_signal_handlers(self):
        """
        Initialize signal handlers to process OS signalling
        """
        for s in [signal.SIGINT, signal.SIGTERM, signal.SIGHUP]:
            signal.signal(s, DDTBSignalHandler)

    def __del__(self):
        logs.session.debug('Closing customer session: %s' % self.session_key)
        if self.rfd != None:
            os.close(self.rfd)
        if self.wfd != None:
            os.close(self.wfd)

    def run(self):
        """
        Run the client tunnel negotiation process, until everything is finished
        for the client.
        """

        logs.session.debug('Customer session %s:%s: init' % self.remote_address)

        # Under some conditions, os.read returns empty string (EOF). 'continue' in 'except IndexError'
        # is reached and about 8000 lines of debug per second is generated. The self.rfd is os.pipe()
        # created right before os.fork() (set separately from __init__). Changed this to use select.select(),
        # added checks + time.sleep for cases of string from os.read() is empty / is EOF, or command is invalid.
        #
        # Under some (possibly other) conditions, a client can hang and that leaves us with hung
        # child process. The select.select() should limit this to 30 seconds per state.

        while True:
            if not (select.select([self.rfd], [], [], 30)):
                logs.session.debug('os.read() from pipe timed out (30 seconds), abandon client at %s:%s.' % (self.remote_address) )
                os.write(self.wfd,response_code(NEGOTIATION_TIMEOUT))
                break

            request = os.read(self.rfd,2048)

            if not request:
                logs.session.debug('os.read() from pipe got EOF, abandon client at %s:%s.' % (self.remote_address) )
                os.write(self.wfd,response_code(SERVER_ERROR))
                break

            lines = request.split('\r\n')
            cmd = lines[0]

            try:
                command = cmd.split()[0]
            except IndexError:
                if self.iters == 0:
                    self.iters = 1
                    logs.session.debug('Invalid command from client at %s:%s: %s' % (self.remote_address, cmd) )
                    time.sleep(2)
                    continue
                else:
                    logs.session.debug('Invalid command "%s", abandon client at %s:%s.' % (cmd, self.remote_address) )
                    os.write(self.wfd,response_code(INVALID_REQUEST)) 
                    break

            if self.state == 'init':
                if command[:7] != 'VERSION':
                    logs.session.debug('%s: Expected VERSION got %s' % (self.state,request))
                    os.write(self.wfd,response_code(INVALID_REQUEST))
                    continue

                ver = cmd.split('=')[1].strip()
                if ver in TUNNEL_SUPPORTED_VERSIONS:
                    os.write(self.wfd,'%s\r\n' % TUNNEL_CAPABILITIES)
                    self.state = 'auth'
                else:
                    logs.session.debug('%s: Unsupported version got %s' % (self.state,ver))
                    os.write(self.wfd,response_code(UNSUPPORTED_VERSION))

            elif self.state == 'auth':
                if command != 'AUTHENTICATE':
                    logs.session.debug('%s: Expected AUTHENTICATE got %s' % (self.state,request))
                    os.write(self.wfd,response_code(INVALID_REQUEST))
                    continue
                try:
                    authtype = cmd.split()[1]
                except IndexError:
                    logs.session.debug('%s: Invalid AUTHENTICATE got %s' % (self.state,request))
                    os.write(self.wfd,response_code(INVALID_REQUEST))
                    continue
                if authtype == 'ANONYMOUS':
                    os.write(self.wfd,response_code(OK))
                    self.state='create'
                elif authtype == 'DIGEST-MD5':
                    (challenge,self.md5) = self.manager.auth.challenge()
                    os.write(self.wfd,challenge)
                    self.state='md5'
                else:
                    os.write(self.wfd,response_code(AUTHFAIL))

            elif self.state == 'md5':
                (state,ackmsg) = self.manager.auth.response(self.md5,request)                

            # Authentication failure
            # When SASL MD5 backend returns 'state' and 'ackmsg', there is no information about user anymore.
            # We must look back to 'request' from client, base64-decode it and then parse. The .partition()
            # function is used, because strings like 'nonce="m8CafgABCDE="' would be incorrectly interpreted
            # by .split() as having three components and dict() would fail.

                if not state.k or not ackmsg:
#                    logs.session.debug('AUTHFAIL')
                    req_dict = dict(item.partition('=')[0::2] for item in base64.b64decode(request).split(','))
                    logs.auth.info('Client %s FAILED authentication.' % (req_dict['username'].decode('utf-8')) )
                    os.write(self.wfd,response_code(AUTHFAIL))
                    break

            # Authentication successful, but there could be ValueError from ORM
#                logs.session.debug('AUTHSUCCESS: %s, %s' % (self.state, ackmsg))
                logs.auth.info('Authentication successful for login "%s"' % (state.entity.decode('utf-8')))
                client = 'N/A' 
                try:
                    login = unicode(state.entity)
                    self.manager.database.store.autoreload()
                    client = self.manager.database.client_details(login=login)
                    self.client_id = client.id
                except ValueError:
                    # Client not found, authentication failed.
                    logs.session.debug('%s: client = %s' %(self.state, client))
                    os.write(self.wfd,response_code(AUTHFAIL))
                    logs.session.debug('%s: PROBLEM: general database problem or user suddenly disappeared.' % (self.state))
                    logs.session.debug('%s: auth.response state was: %s.' % (self.state, state))
                    logs.auth.info('PROBLEM: general database problem or user "%s" suddenly disappeared from database.' % (login))
                    sys.exit(0)
                self.customer_id = client.id
                os.write(self.wfd,'%s%s' % (ackmsg,response_code(OK)))
                self.state='create'
                self.cleanup_old_tunnels()

            elif self.state in ['accept','create']:
                if command != 'Content-length:':
                    logs.session.debug('%s: Expected Content-length got %s' % (self.state, request))
                    os.write(self.wfd,response_code(INVALID_REQUEST))
                    continue
                try:
                    self.accept_create_messages(request)
                except ValueError:
                    os.write(self.wfd,response_code(INVALID_REQUEST))

            elif self.state == 'tunnelup':
                logs.session.debug('State %s' % self.state)
                os.write(self.wfd,request)

            else:
                logs.session.debug('Unexpected message in client state %s: %s' % (
                    self.state,request
                ))
                os.write(self.wfd,response_code(INVALID_REQUEST))

    def __parse_xml__(self,length,data):
        try:
            xmldata = parseString(data)
        except ExpatError:
            logs.session.debug('Error parsing %d bytes: %s' % (length,data))
            time.sleep(5)
            raise ValueError

        # Verify and ill some basic details from the XML data
        request_details = {}
        try:
            tunnel = xmldata.childNodes[0]
            if tunnel.nodeName != 'tunnel':
                logs.session.debug('First node is not tunnel (%s)' % node.nodeName)
                raise ValueError

            attrs = dict(tunnel.attributes.items())
            if not attrs.has_key('action'):
                logs.session.debug('Missing tunnel action')
                raise ValueError

            if attrs['action'] not in TSP_VALID_ACTIONS:
                logs.session.debug('Invalid tunnel action: %s' % attrs['action'])
                raise ValueError
            request_details['tunnel'] = attrs

            for k in ['client','server','broker']:
                try:
                    request_details[k] = tunnel.getElementsByTagName(k)[0]
                except IndexError:
                    pass

        except IndexError:
            logs.session.debug('XML missing required nodes: %s' % data)
            raise ValueError

        # Let the client process whatever they want from the main sections
        return (length,request_details)

    def accept_create_messages(self,message):
        """
        Process a message from client, after authentication phase is finished
        """

        message = ''.join(message.split('\r\n'))
        re_clen = re.compile(r'^Content-length: ([0-9]+)(.*)')

        # Split the input message to possibly multiple XML messages
        messages = []

#        logs.session.debug('%s: Message: "%s"' % (self.state,message))
#        logs.session.debug('%s: start processing messagedata.' % (self.state) )
        while True:
            m = re_clen.match(message)
            if not m:
                break
            c_len = int(m.group(1))
            xmldata = m.group(2)[:c_len]
            messages.append(self.__parse_xml__(c_len,xmldata))
            message = xmldata[c_len:]

        if messages == []:
            logs.session.debug('Invalid messagedata from client')
            time.sleep(1)
            raise ValueError

        for l in message.split('\n'):
            m = re_clen.match(l)
            if m:
                if xmldata != '':
                    try:
                        messages.append(self.__parse_xml__(c_len,xmldata))
                    except ValueError:
                        raise ValueError
                    xmldata = ''
                c_len = m.group(1)
            else:
                xmldata += '%s\n' % l
        if c_len and xmldata != '':
            try:
                messages.append(self.__parse_xml__(c_len,xmldata))
            except ValueError,e:
                raise ValueError
#        logs.session.debug('%s: syntactically correct messagedata from client.' % (self.state))

        for msg in messages:
            msg_len = msg[0]
            req = msg[1]

            tunnel = req['tunnel']
            action = tunnel['action']

            if tunnel.has_key('type'):
                tunnel_type = tunnel['type']
                if tunnel_type not in TUNNEL_SUPPORTED_TYPES:
                    logs.session.debug('Unsupported tunnel type: %s' % tunnel_type)
                    os.write(self.wfd,response_code(UNSUPPORTED_TUNNELTYPE))
                    return
                self.tunnel_type = tunnel_type

            if action == 'accept':
#                logs.session.debug('%s: tunnel action: accept.' % (self.state))
                self.client_accept_tunnel(req)
            elif action == 'create':
#                logs.session.debug('%s: tunnel action: create.' % (self.state))
                self.client_create_tunnel_request(req)
            else:
                logs.session.debug('Unsupported client action: %s' % action)
                raise ValueError
#        logs.session.debug('%s: processed %d messages in messagedata from client.' % (self.state, len(messages)))

    def client_accept_tunnel(self,req):
        """
        Client has accepted the suggested tunnel configuration so we shall
        create relevant interfaces and add the customer to our database.

        Req is a pre-parsed dictionary with XML nodes for further details.
        """
        if self.state != 'accept':
            logs.session.debug("%s: accept XML message %s" % (
                self.state,req
            ))
            raise ValueError

        tunnelconfig = TSPTunnelConfig(
            self.manager,
            dict(self)
        )
        tunnelconfig.configure()
        now = datetime.datetime.now()
        keepalive = self.keepalive and int(self.keepalive) or 0
        tunnel_db_details = {
            'client_id':    self.client_id,
            'client_port':  int(tunnelconfig['client_port']),
            'client_ipv4':  unicode(tunnelconfig['client_ipv4']),
            'client_ipv6':  unicode(tunnelconfig['client_ipv6']),
            'server_ipv4':  unicode(tunnelconfig['server_ipv4']),
            'server_ipv6':  unicode(tunnelconfig['server_ipv6']),
            'prefix':       unicode(tunnelconfig['prefix']),
            'tunnel_type':  unicode(self.tunnel_type),
            'keepalive':    keepalive,
            'start_time':   now,
            'valid_until':  now + datetime.timedelta(days=1),
        }
        self.manager.database.register_tunnel(self.client_id,tunnel_db_details)
#        logs.session.debug('%s: processed "accept" message in messagedata from client.' % (self.state) )
        logs.session.debug('%s: tunnel UP, client_id %d, allocated prefix %s' % (
            self.state, self.client_id, self['prefix'])
        )
        logs.auth.info('Client %s logged on' % self.manager.database.client_details(self.client_id).login)
        
        self.state = 'tunnelup'
        # We now exit the client: no further commands expected in
        # this context. If we later implement 'info' or 'delete'
        # these would need different processing in state machine.
        sys.exit(0)

    def client_create_tunnel_request(self,req):
        """
        Parse customer XML 'create' request for tunnel, validating all
        relevant fields properly. If all parameters are OK, we update
        self (dictionary) with parameter used for TSPTunnelConfig after
        customer sends 'accept' message.
        """
        if self.state != 'create':
#            logs.session.debug("%s: 2nd create XML message %s" % (
#                self.state,req
#            ))
#            logs.session.debug('%s: tunnel request was already accepted, not in create state (neglect this message).' % (self.state) )
            return

        try:
            client = req['client']
        except KeyError:
            logs.session.debug('No client node in request')
            raise ValueError

        try:
            a_node = client.getElementsByTagName('address')[0]
            a_attr = dict(a_node.attributes.items())
        except IndexError:
            logs.session.debug('Client XML missing address element')
            raise ValueError

        try:
            a_type = a_attr['type']
            if a_type != 'ipv4':
                logs.session.debug('Unsupported address type %s' % a_type)
                raise ValueError
            client_address = a_node.childNodes[0].nodeValue
        except KeyError:
            logs.session.debug('Invalid client XML: no client address config')
            raise ValueError

        if client_address != self.remote_address[0]:
            logs.session.debug('Address differs (reported %s, packet received from %s), setting NAT flag' % (client_address, self.remote_address[0]) )
            self.nat = True

        for tag in ['keepalive','router','prefix']:
            try:
                value = client.getElementsByTagName(tag)[0].value
            except AttributeError:
                value = None
            except IndexError:
                value = None
            setattr(self,tag,value)

        if self.keepalive is not None:
            try:
                self.keepalive = int(self.keepalive)
            except ValueError:
                logs.session.debug('Invalid keepalive value from client: %s' % self.keepalive)
                raise ValueError
            self.keepalive = max([ self.config.broker.cleanup_interval, self.keepalive ])
        else:
            self.keepalive = None

        allocation = self.manager.prefixes.find_next(self.customer_id)
        self.update({
            'customer_id':      self.customer_id,
            'client_port':      str(self.remote_address[1]),
            'client_ipv4':      str(self.remote_address[0]),
            'client_ipv6':      allocation.client_ipv6.address,
            'prefix_mask':      allocation.mask,
            'server_ipv4':      self.server_ipv4,
            'server_ipv6':      allocation.server_ipv6.address,
            'server_port':      self.manager.server_port,
            'tunnel_type':      self.tunnel_type,
            'prefix':           allocation.network,
        })

        if self.keepalive is not None:
            self['keepalive'] = TUNNEL_KEEPALIVE_XML_REPLY % {
                'client_ipv6': '%s:0' % allocation.client_ipv6,
                'keepalive': c_keepalive_interval
            }
        else:
            self['keepalive'] = ''

#        logs.session.debug('%s: client request OK, replying with tunnel parameters.' % (self.state))
        self.state = 'accept'
        reply = '%s%s\r\n' % (response_code(OK),TUNNEL_INFO_XML_REPLY % self)
        os.write(self.wfd,'Content-length: %d\r\n%s' % (len(reply),reply))

    def cleanup_old_tunnels(self):
        """
        Remove existing tunnels for successfully logged in user before new
        tunnel is created.
        """
        if self.client_id == None:
            logs.session.info('ERROR: user cleanup_old_tunnels but no client_id')
            return

        for tunnel in self.manager.database.tunnels(client_id=self.client_id):
            logs.session.info('%s: removing old tunnel for client_id %s.' % (self.state, self.client_id))
            self.manager.tunnelconfigs.deconfigure_tunnel(tunnel)
            self.manager.database.unregister_tunnel(tunnel.id)

class CustomerSessions(dict):
    """
    Dictionary containing the tunnelbroker child processes
    """
    def __init__(self,manager):
        self.manager = manager
        self.database = manager.database

        self.lookup_count = 0
        self.session_fds = {}

    def __setitem__(self,session_key,session):
        if self.has_key(session_key):
            raise DDTBError('Duplicate session key: %s' % session_key)
        dict.__setitem__(self,session_key,session)
        self.session_fds[session.pr] = session

    def remove(self,session):
        session_key = session.session_key
        if self.has_key(session_key):
            self.pop(session_key)
        else:
            logs.ddtb.debug('Session key to remove not found: %s' % session_key)
        if self.session_fds.has_key(session.pr):
            self.session_fds.pop(session.pr)

    def lookup_fd(self,fd):
        return self.session_fds[fd]

class ClientSessionManager(object):
    """
    Main DDTB process for managing client sessions.
    Forks a CustomerSession process for each new customer connection
    """
    def __init__(self,config):
        crypt = TBCrypt()
        self.config = config
        self.server_ipv4 = self.config.broker.tunnelip
        self.server_port = self.config.broker.port
        self.cleanup_interval = self.config.broker.cleanup_interval

        # Timestamp for last cleanup of expired tunnels
        self.last_cleanup = None

        self.socket = None
        self.poller = None

        self.database = DDTBDatabase(self.config)
        self.sessions = CustomerSessions(self)

# We need to unencrypt the client passwords, because SASL-MD5
# authentication needs users' plaintext passwords. Just modify
# Client-objects in place (in init_user_cache()).

        self.auth = DDTBLoadAuthenticator(config)

        self.init_user_cache()

        self.prefixes = CustomerAddressPool(
            self.database,
            self.config.prefix.allocation_prefix,
            self.config.prefix.customer_prefix_size
        )

        self.tunnelconfigs = TSPTunnelConfigManager(
            server_ipv4=self.server_ipv4,server_port=self.server_port
        )

        self.config.init_system()
        self.init_db_tunnels()
        self.ipcserver = None

    def init_user_cache(self):
        crypt = TBCrypt()  
        clients = self.database.clients()
        
        for client in clients:
#            logs.ddtb.debug('Process client "%s"' % (client))
            client.passwd = crypt.decryptPassword(base64.b64decode(client.iv), base64.b64decode(client.passwd), base64.b64decode(self.config.ipc.db_key)).decode('utf-8')

        self.auth.user_cache.clear()
        self.auth.user_cache.update(clients)
        logs.ddtb.debug('User cache initialized, %d user accounts.' % (len(self.auth.user_cache)))

    def change_user_cache(self, login):
        crypt = TBCrypt()
        client = self.database.client_details(login)
        client.passwd = crypt.decryptPassword(base64.b64decode(client.iv), base64.b64decode(client.passwd), base64.b64decode(self.config.ipc.db_key)).decode('utf-8')
        self.auth.user_cache.update([client])
        logs.ddtb.debug('Updated user %s password in user cache.' % (login))

    def init_signal_handlers(self):
        """
        Initialize signal handlers to process OS signalling
        """
        for s in [signal.SIGINT,signal.SIGTERM,signal.SIGHUP]:
            signal.signal(s,DDTBSignalHandler)

    def init_db_tunnels(self):
        """
        Initialize tunnels configured to database to system network setup
        """
        tunnels = self.database.tunnels()
        self.tunnelconfigs.sync_db_tunnels(tunnels)

    def cleanup_expired(self):
        """
        Deconfigure tunnels which are no more valid in our DB, but only do
        it when EXPIRED_CLEANUP_INTERVAL has passed since last cleanup.
        """
        if self.last_cleanup is not None:
            now = time.mktime(time.localtime())
            if now > self.last_cleanup + self.config.broker.cleanup_interval:
                return

        for tunnel in self.database.expired_tunnels():
            try:
                self.tunnelconfigs.deconfigure_tunnel(tunnel)
                self.database.unregister_tunnel(tunnel.id)
            except:
                logs.ddtb.error('Cleanup of expired tunnel failed')

        self.last_cleanup = time.mktime(time.localtime())

    def msg_from_client(self):
        """
        Process a message received from a client process
        """
        (msg, sender_address) = self.socket.recvfrom(2048)
        if len(msg) < 8:
            logs.ddtb.debug('Too short message from %s:%s' % sender_address)
            return
        (sender_ip, sender_port) = sender_address

        session_key = '%s:%s' % (sender_ip, sender_port)
        if self.sessions.has_key(session_key):
            session = self.sessions[session_key]
        else:
            logs.ddtb.debug('New session: %s' % session_key)
            session = CustomerSession(
                manager=self,
                session_key=session_key,
                server_ipv4=self.server_ipv4,
                remote_address=sender_address,
            )
            (cr, session.pw) = os.pipe()
            (session.pr, cw) = os.pipe()
            pid = os.fork()

            if pid == 0:
                # Child process: close parent side FDs and run session
                os.close(session.pr)
                os.close(session.pw)

                # Initialize signal handlers separately for child process
                session.init_signal_handlers()

                session.pid = os.getpid()
                session.rfd = cr
                session.wfd = cw

                # Ensure that we don't have IPC servers listening to in child processes
                if self.ipcserver and isActive(self.config):
                    self.ipcserver.stop()

                try:
                    session.run()
                except ShutDownException,e:
                    del(session)
                sys.exit(0)

            else:
                # Close child side FDs
                os.close(cw)
                os.close(cr)
                session.pid = pid
                try:
                    self.sessions[session_key] = session
                except DDTBError,e:
                    logs.ddtb.debug(e)
                    return

                logs.ddtb.debug('Registering child FD %d for %s:%s' % (
                    session.pr,
                    session.remote_address[0],
                    session.remote_address[1],
                ))
                self.poller.register(session.pr,select.POLLIN|select.POLLERR|select.POLLHUP)

        (seq,session.last_pkt) = struct.unpack('!LL',msg[:8])
        seq = 0x0fffffff & seq

        if session.seq > 0:
            if seq < session.seq or seq - session.seq > 1:
                logs.ddtb.error('SEQ error: old %d new %d' % (session.seq,seq))
                return
        session.seq = seq

        if len(msg) > 8:
            #logs.ddtb.debug('%d bytes to session FD %d' % ( len(msg[8:]),session.pw))
            os.write(session.pw,msg[8:])
        else:
            msg = '%s%s' % (msg,response_code(OK))
            self.socket.sendto(msg,session.remote_address)

    def msg_from_child(self, fd, ev):
        """
        Message from a child process. Either indicates finished child or the
        msg is forwarded to remote address
        """
        try:
            session = self.sessions.lookup_fd(fd)
            msg_hdr = struct.pack('!LL', session.seq|0xf0000000, session.last_pkt)
        except KeyError:
            logs.ddtb.error('Input from unknown FD %s' % fd)
            return

        # Child process closing
        if ev in [select.POLLERR,select.POLLHUP]:
            self.socket.sendto(msg_hdr, session.remote_address)
            logs.ddtb.debug('Unregistering child FD %d' % session.pr)
            self.poller.unregister(session.pr)
            while True:
                (pid, status) = os.waitpid(0, os.WNOHANG)
                if (pid != 0 or status != 0):
                    logs.ddtb.debug('Child with PID %d exited with status code %d.' % (pid, status))
                else:
                    break
            
            self.sessions.remove(session)
            return

        nmsg = os.read(session.pr,2048)
        if nmsg is None:
            self.socket.sendto(msg_hdr, session.remote_address)
            logs.ddtb.debug('Unregistering child FD %d' % session.pr)
            self.poller.unregister(session.pr)
            while True:
                (pid, status) = os.waitpid(0, os.WNOHANG)
                if (pid != 0 or status != 0):
                    logs.ddtb.debug('Child with PID %d exited with status code %d.' % (pid, status))
                else:
                    break
            
            self.sessions.remove(session)
            return

        self.socket.sendto(msg_hdr + nmsg, session.remote_address)

    def shutdown(self):
        if self.ipcserver and isActive(self.config):
            logs.ddtb.debug('Stopping IPC server')
            self.ipcserver.stop()

        child_pids = [session.pid for session in self.sessions.values()]
        if len(child_pids) == 0:
            return
        # TODO - do real PID waiting
        logs.ddtb.debug('Waiting for children: %s' % ','.join(str(x) for x in child_pids))

        time.sleep(1)

    def run(self):
        """
        Run the TTDB tunnel broker main loop
        """

        self.init_signal_handlers()

        bind_ip = self.config.broker.serverip
        bind_port = self.config.broker.port

        logs.ddtb.info('Starting DDTB on %s:%s' % (bind_ip,bind_port))
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((bind_ip,bind_port))
        except socket.error,e:
            logs.ddtb.error('Error binding socket: %s' % e)
            print 'Error binding to server address'
            sys.exit(1)
        except socket.gaierror,e:
            logs.ddtb.error('Error binding socket: %s' % e)
            print 'Error binding to server address'
            sys.exit(1)

        # Start IPC daemon if it isn't yet started
        if self.config.ipc.active and self.ipcserver == None and not isActive(self.config):
            logs.ddtb.info("Starting RPC server on port: %d" % int(self.config.ipc.port))
            self.ipcserver = TBRPCServer(self.config, self.database, self.sessions, self.prefixes)
            self.ipcserver.start()

        self.poller = select.poll()
        logs.ddtb.debug('Registering master FD %d to poller' % self.socket.fileno())
        self.poller.register(self.socket, POLL_READ_ONLY)

        while True:
            try:
                events = self.poller.poll(POLLER_TIMEOUT)
                for fd, ev in events:
                    if fd == self.socket.fileno():
                        #logs.ddtb.debug('Client message from FD %d' % fd)
                        self.msg_from_client()
                    else:
                        #logs.ddtb.debug('Child message from FD %d' % fd)
                        self.msg_from_child(fd,ev)
                # This only does something every EXPIRED_CLEANUP_INTERVAL
                self.cleanup_expired()

            except select.error,(ecode,emsg):
                logs.ddtb.debug('Select interrupted: %s' % emsg)
                time.sleep(0.1)

            except ReconfigureException,e:
                logs.ddtb.debug('SIGHUP received, update user cache.' % e)
                self.init_user_cache()
                continue

            except ShutDownException,e:
                logs.ddtb.debug('Stopping SessionManager: %s' % e)
                self.cleanup_expired()
                self.shutdown()
                break
