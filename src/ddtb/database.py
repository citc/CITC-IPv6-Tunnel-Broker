 # Copyright (C) CITC, Communications and Information Technology Commission,
 # Kingdom of Saudi Arabia.
 #
 # Developed by CITC Tunnel Broker team, tunnelbroker@citc.gov.sa.
 #
 # This software is released to public domain under GNU General Public License
 # version 2, June 1991 or any later. Please see file 'LICENSE' in source code
 # repository root.

"""
Implements the database model for DDTB storm ORM mapping and local
database access classes
"""

import datetime
import re
from storm.locals import *
from MySQLdb import OperationalError,ProgrammingError

from ddtb import DDTBError

# Note, these table specs work only in mysql
DDTB_MYSQL_TABLES = [
"""
CREATE TABLE IF NOT EXISTS PREFIX_ALLOC (
    prefix      varchar(43) COLLATE utf8_unicode_ci NOT NULL COMMENT 'Prefix to reserve',
    created     timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    prefixlen   smallint(6) DEFAULT NULL,
    UNIQUE KEY  prefix (prefix)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
""",
"""
CREATE TABLE IF NOT EXISTS CLIENT (
    id        int(10) unsigned NOT NULL AUTO_INCREMENT COMMENT 'Client ID',
    login     varchar(32) COLLATE utf8_unicode_ci NOT NULL COMMENT 'Login name for this user',
    email     varchar(320) COLLATE utf8_unicode_ci COMMENT 'Email address of this user',
    mobile    varchar(14) COLLATE utf8_unicode_ci COMMENT 'Mobile phone number of this user',
    ipaddress varchar(37) COLLATE utf8_unicode_ci COMMENT 'IP address used during registration',
    name      varchar(255) COLLATE utf8_unicode_ci NOT NULL COMMENT 'Real (descriptive) name of individual or organization',
    iv        varchar(32) COLLATE utf8_unicode_ci COMMENT 'Base64 (prefer RFC3548/4648) of IV (IV size is AES block size of 128 bits)',
    passwd    varchar(255) COLLATE utf8_unicode_ci NOT NULL COMMENT 'Base64 (prefer RFC3548/4648) of encrypted password',
    max_prefix int(10) unsigned NOT NULL DEFAULT '64' COMMENT 'Maximum allowed prefix (typically 64) length that client can request',
    min_prefix int(10) unsigned NOT NULL DEFAULT '48' COMMENT 'Minimum allowed prefix (typically 48) length that client can request',
    PRIMARY KEY (id)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
""",
"""
CREATE TABLE IF NOT EXISTS PREFIX (
    id int(10) unsigned NOT NULL AUTO_INCREMENT COMMENT 'Prefix ID',
    prefix varchar(43) COLLATE utf8_unicode_ci NOT NULL COMMENT 'Up to full IPv6 address plus slash and three digits',
    type varchar(3) COLLATE utf8_unicode_ci NOT NULL COMMENT 'Either string v4 or v6',
    client_id int(10) unsigned DEFAULT NULL COMMENT 'Client who owns this prefix, NULL means us',
    we_assign tinyint(1) DEFAULT '0' COMMENT 'Prefix from which we give out blocks to our clients who do not have their own IP addresses',
    PRIMARY KEY (id),
    KEY client_id (client_id),
    CONSTRAINT FOREIGN KEY (client_id) REFERENCES CLIENT(id) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=18 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
""",
"""
CREATE TABLE IF NOT EXISTS SERVER (
    id int(10) unsigned NOT NULL AUTO_INCREMENT COMMENT 'Server ID',
    server_id varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'Known tunnel server unique ID (typically IP address), set in server configuration file',
    config_ip varchar(39) COLLATE utf8_unicode_ci NOT NULL COMMENT 'IP where server listens for TCP connections from broker',
    config_port int(5) unsigned DEFAULT '3653' COMMENT 'TCP port where server listens for connections from broker',
    tunnel_ipv4 varchar(15) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'Server tunnel end IPv4 address (if any)',
    tunnel_ipv6 varchar(39) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'Server tunnel end IPv6 address (if any)',
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
""",
"""
CREATE TABLE IF NOT EXISTS TUNNEL (
    id int(10)  unsigned NOT NULL AUTO_INCREMENT COMMENT 'Tunnel ID',
    client_port int(10) unsigned DEFAULT NULL COMMENT 'UDP (or TCP) port from where client connection originates',
    client_ipv4 varchar(15) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'Client side IPv4 address of tunnel endpoint',
    server_ipv4 varchar(15) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'Server side IPv4 address of tunnel endpoint',
    client_ipv6 varchar(39) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'Client side IPv6 address of tunnel endpoint',
    server_ipv6 varchar(39) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'Server side IPv6 address of tunnel endpoint',
    prefix      varchar(43) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'Address space routed to customer',
    tunnel_type varchar(32) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'Should be one defined in RFC5572 Section 7',
    client_id   int(10) unsigned DEFAULT NULL COMMENT 'Reference to client ID',
    keepalive   int(10) unsigned DEFAULT NULL COMMENT 'Keepalive period (typically 30 seconds) for connections behind NAT',
    start_time  datetime DEFAULT NULL COMMENT 'When this tunnel was created',
    valid_until datetime DEFAULT NULL COMMENT 'When this tunnel becomes invalid and is shut down',
   PRIMARY KEY (id),
   KEY client_id (client_id), CONSTRAINT FOREIGN KEY (client_id) REFERENCES CLIENT(id) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=362 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
""",
"""
CREATE TABLE IF NOT EXISTS DELEGATION (
    id                  int(10) unsigned NOT NULL AUTO_INCREMENT COMMENT 'Reverse DNS delegation ID',
    dns_server          varchar(39) COLLATE utf8_unicode_ci NOT NULL COMMENT 'Up to 39 characters for IPv6 address of DNS server',
    tunnel_id int(10)   unsigned DEFAULT NULL COMMENT 'References tunnel with which this reverse delegation is associated',
    PRIMARY KEY         (id),
    KEY tunnel_id (tunnel_id), CONSTRAINT FOREIGN KEY (tunnel_id) REFERENCES TUNNEL(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
""",
"""
CREATE TABLE IF NOT EXISTS AUTHENTICATION_METHOD (
    id          int(10) unsigned NOT NULL AUTO_INCREMENT COMMENT 'Authentication method ID',
    method      varchar(64) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'Name of authentication type such as plain, anonymous, digest-md5 etc.',
    PRIMARY KEY (id)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
""",
"""
CREATE TABLE IF NOT EXISTS BROKER (
    id          int(10) unsigned NOT NULL AUTO_INCREMENT COMMENT 'Broker ID',
    broker_id   varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL COMMENT 'Known broker server unique ID (typically IP address), set in broker configuration file',
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
""",
"""
CREATE TABLE IF NOT EXISTS BROKER_AUTHENTICATION (
    id          int(10) unsigned NOT NULL AUTO_INCREMENT COMMENT 'Allowed broker-authentication pair ID',
    broker_id   int(10) unsigned NOT NULL COMMENT 'Broker ID',
    authentication_id int(10) unsigned NOT NULL COMMENT 'Authentication ID',
    PRIMARY KEY (id),
    KEY broker_id (broker_id),
    KEY authentication_id (authentication_id),
    CONSTRAINT FOREIGN KEY (broker_id) REFERENCES BROKER (id),
    CONSTRAINT FOREIGN KEY (authentication_id) REFERENCES AUTHENTICATION_METHOD (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
"""
]

class Prefix_Alloc(object):
    __storm_table__ = 'PREFIX_ALLOC'

    prefix = Unicode(primary=True)
    created = DateTime()
    prefixlen = Int()

class Client(object):
    __storm_table__ = 'CLIENT'

    id = Int(primary=True)
    login = Unicode()
    email = Unicode()
    mobile = Unicode()
    ipaddress = Unicode()
    name = Unicode()
    iv = Unicode()
    passwd = Unicode()
    max_prefix = Int()
    min_prefix = Int()

    def __str__(self):
        return "Client login '%s', name '%s'" % (self.login, self.name)

class Prefix(object):
    """
    Database table for storing client IPv6 prefix allocations
    """
    __storm_table__ = 'PREFIX'

    id = Int(primary=True)
    prefix = Unicode()
    type = Unicode()
    client_id = Int()
    client = Reference(client_id, Client.id)
    we_assign = Int()

    def __str__(self):
        return "Prefix %s, type %s for client_id %d" % (self.prefix, self.type, client_id)

class Server(object):
    """
    Database table for the DDTB server IP configuration
    """
    __storm_table__ = 'SERVER'

    id = Int(primary=True)
    server_id = Unicode()
    config_ip = Unicode()
    config_port = Int()
    tunnel_ipv4 = Unicode()
    tunnel_ipv6 = Unicode()

class Tunnel(object):
    """
    Database table for client tunnel status details
    """
    __storm_table__ = 'TUNNEL'

    id = Int(primary=True)
    client_port = Int()
    client_ipv4 = Unicode()
    server_ipv4 = Unicode()
    client_ipv6 = Unicode()
    server_ipv6 = Unicode()
    prefix = Unicode()
    tunnel_type = Unicode()
    client_id = Int()
    client = Reference(client_id, Client.id)
    keepalive = Int()
    start_time = DateTime()
    valid_until = DateTime()

    def __str__(self):
        return "Tunnel from %s:%s for prefix %s, started %s, valid until %s" % (
           self.client_ipv4, self.client_port,
           self.prefix, start_time, valid_until)

class Delegation(object):
    """
    Database table to map tunnel delegations
    """
    __storm_table__ = 'DELEGATION'

    id = Int(primary=True)
    dns_server = Unicode()
    tunnel_id = Int()
    tunnel = Reference(tunnel_id, Tunnel.id)

class Auth_method(object):
    """
    Database table to store authentication method types available
    """
    __storm_table__ = 'AUTHENTICATION_METHOD'

    id = Int(primary=True)
    method = Unicode()

class Broker(object):
    """
    Database table to define unique DDTB broker instances
    """
    __storm_table__ = 'BROKER'
    id = Int(primary=True)
    broker_id = Unicode()

class Broker_auth(object):
    """
    Database table to map defined authentication method to Broker instance
    """
    __storm_table__ = 'BROKER_AUTHENTICATION'

    id = Int(primary=True)
    broker_id = Int()
    broker = Reference(broker_id, Broker.id)
    authentication_id = Int()
    authentication = Reference(authentication_id, Auth_method.id)

class DDTBDatabase(object):
    """
    Database access class for database queries.
    """

    def __init__(self,config):
        """
        The connection parameter should be a valid storm ORM DB
        access string, for example:
            mysql://ddtb:ddtbpassword@localhost:3306/TB
        """
        if re.search("[^a-zA-Z0-9_\+=_\-]", config.database.password):
            error = 'Database user ' + config.database.user + ' password contains illegal character (for example, "/" is not allowed).'
            raise DDTBError(error)

        self.database = create_database(config.database.connection)
        self.__store = None

    def __getattr__(self,attr):
        if attr == 'store':
            if self.__store is None:
                try:
                    self.__store = Store(self.database)
                except OperationalError,e:
                    raise DDTBError('Error connecting to database: %s' % e[1])
                except:
                    raise DDTBError('Error opening database store')
            self.__store.autoreload()
            return self.__store
        return getattr(self.database,attr)

    def create_database_tables(self):
        """
        Create empty database tables based on our database model. Note that
        an empty database with GRANT ALL ON <database>.* must be executed and
        user account created to DB before this can be done. We only create
        tables, not databases or accounts.
        """
        for cmd in DDTB_MYSQL_TABLES:
            try:
                self.store.execute(cmd)
            except ProgrammingError:
                raise DDTBError('Error creating database tables')
        self.store.commit()
        self.__store = None

    def prefixes(self,client_id=None):
        """
        Returns the prefixes defined for given username from database,
        or all prefixes if no client_id is given
        """
        if client_id is not None:
            entries = self.store.find(Prefix,Prefix.client_id == client_id)
        else:
            entries = self.store.find(Prefix)
        self.__store = None
        return entries

    def tunnels(self,client_id=None):
        """
        Returns the tunnels defined for given username from database,
        or all tunnels if no client_id is given
        """
        if client_id is not None:
            entries = self.store.find(Tunnel,Tunnel.client_id == client_id)
        else:
            entries = self.store.find(Tunnel)
        self.__store = None
        return entries

    def expired_tunnels(self):
        """
        Return list of tunnels whose validity period is past now
        """
        self.store.flush()
        tunnels = self.store.find(
            Tunnel,
            Tunnel.valid_until < datetime.datetime.now()
        )
        self.__store = None
        return tunnels

    def clients(self):
        """
        Returns all registered clients from the database
        """
        self.store.autoreload()
        clients = self.store.find(Client)
        self.__store = None
        return clients

    def client_details(self, login):
        """
        Return client details for specific user login or ID
        """
        try:
            entry = self.store.find(Client,Client.login == unicode(login))[0]
            self.store.reload(entry)
            self.__store = None
            return entry
        except IndexError:
            try:
                id = int(login)
                try:
                    entry = self.store.find(Client,Client.id == id)[0]
                    self.__store = None
                    return entry
                except IndexError:
                    pass
            except ValueError:
                pass
        raise ValueError('No such user')


    def unregister_prefix(self,client_id,prefix):
        """
        Remove allocation for a single prefix with given client_id
        """
        self.store.flush()
        self.__store = None

    def register_prefix(self,client_id,prefix):
        """
        Register a single prefix for given client_id
        """
        self.store.flush()
        entry = Prefix()
        try:
            client = self.store.find(Client,Client.id == client_id)[0]
        except IndexError:
            raise DDTBError('No such client: %s' % client_id)
        entry.client_id = client.id
        entry.prefix = unicode(prefix.network)
        entry.prefixlen = prefix.mask
        entry.type = unicode(prefix.prefix_type)
        self.store.add(entry)
        self.store.commit()
        self.__store = None

    def unregister_tunnel(self,tunnel_id):
        """
        Remove registeration for given tunnel with given user ID
        """
        try:
            tunnel = self.store.find(Tunnel,Tunnel.id==tunnel_id)[0]
            client_login = tunnel.client.login
            self.store.remove(tunnel)
            self.store.commit()
            logs.auth.info("Tunnel for client %s closed" % client_login)
        except IndexError:
            raise DDTBError('No such tunnel ID: %s' % tunnel_id)
        self.__store = None

    def unregister_client(self,login):
        """
        Unregister a client entry from the database
        """
        self.store.flush()
        try:
            client = self.store.find(Client,Client.login==unicode(login.decode('utf8')))[0]
            logs.auth.info('Unregistering client: %s (%s)' % (client.login, client.name))
            self.store.remove(client)
            self.store.commit()
        except IndexError:
            raise DDTBError('No such client: %s' % login)
        self.__store = None

    def register_client(self, login, name, iv, passwd, email, mobile, ipaddress, max_prefix,min_prefix):
        """
        Register a new client entry to the database
        """
        try:
            self.store.find(Client,Client.login==unicode(login))[0]
            raise DDTBError('Customer already registered: %s' % unicode(login))
        except IndexError:
            pass
        client = Client()
        client.login      = unicode(login)
        client.name       = unicode(name)
        client.iv         = unicode(iv)
        client.passwd     = unicode(passwd)
        client.email      = unicode(email)
        client.mobile     = unicode(mobile)
        client.ipaddress  = unicode(ipaddress)
        client.min_prefix = min_prefix
        client_max_prefix = max_prefix
        self.store.add(client)
        self.store.flush()
        self.store.commit()
        logs.auth.info('Registered client: %s (%s)' % (login,name))
        self.__store = None
        return client.id

    def checkLogin(self, login, passwd):
        try:
            entry = self.store.find(Client,Client.login==unicode(login)).one()
            if not entry:
                logs.auth.info("Client with login %s not found." % login)
                return False
            elif not unicode(passwd) == entry.passwd:
                logs.auth.info("Client with login %s tried wrong credentials." % login)
                return False

            logs.auth.info("Client with login %s authenticated." % login)
            return True

        except IndexError:
            raise DDTBError('Client with login %s not found (IndexError).' % login)

    def update_password(self, login, iv, NewPasswd):
        try:
            self.store.find(Client, Client.login == unicode(login)).set(passwd=unicode(NewPasswd))
            self.store.find(Client, Client.login == unicode(login)).set(iv=unicode(iv))
            self.store.commit()
            self.__store = None
            return True

        except IndexError:
            raise DDTBError('Client with login %s not found, cannot update password' % login)

    def register_tunnel(self,client_id,tunnel_details):
        """
        Register given tunnel to given user ID
        """
        tunnel = Tunnel()
        for k,v in tunnel_details.items():
            setattr(tunnel,k,v)
        self.store.add(tunnel)
        self.store.commit()
        self.__store = None
