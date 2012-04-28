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
DDTB tunnel classes
"""

import sys,os,time
from subprocess import call,Popen,PIPE

from ddtb import DDTBError

# Offset used in utun_table replacement calculation
TSP_RTABLE_OFFSET = 1000

# Options required for a TSPTunnelConfig class instance
TSP_MANDATORY_FLAGS = [
    'prefix','server_ipv4',
    'client_port','client_ipv4','client_ipv6',
]

TSP_TUNNEL_LINK_SETUP_COMMANDS = [
    'ip link add name %(interface)s type utun',
    'ip addr add %(server_ipv4)s dev %(interface)s',
    'ip -f inet6 addr add %(server_ipv6)s dev %(interface)s',
    'ip link set dev %(interface)s up',
    'ip route del local %(server_ipv4)s dev %(interface)s scope host',
    'ip route add %(prefix)s dev %(interface)s'
]

# This is a separate set from previous, because we need to find ifindex 
# after previous commands before these can be run
TSP_TUNNEL_IPTABLES_ROUTING = [
    'ip rule add fwmark %(ifindex)s table %(utun_table)s',
    'ip route add %(server_ipv4)s dev %(interface)s table %(utun_table)s',
    # Following should be done maybe after all tunnels are setup in this run?
    'ip route flush cache'
]

# Ifindex is known when this is run so we combine the two sets
TSP_TUNNEL_CLEANUP_COMMANDS = [
    'ip route del %(server_ipv4)s dev %(interface)s table %(utun_table)s',
    'ip rule del fwmark %(ifindex)s table %(utun_table)s',
    'ip route del %(prefix)s dev %(interface)s',
    'ip -f inet6 addr del  %(server_ipv6)s dev %(interface)s',
    'ip addr del %(server_ipv4)s/32 dev %(interface)s',
    'ip link delete %(interface)s type utun',
]

TSP_MANGLE_QUEUES = ['PREROUTING','INPUT','OUTPUT']
TSP_MANGLE_COMMAND = 'iptables -t mangle -A %(queue)s -s %(client_ipv4)s -d %(server_ipv4)s -p udp -m multiport --sports %(client_port)s -m multiport --dports %(server_port)s -j MARK --set-mark %(ifindex)s'
TSP_UNMANGLE_COMMAND = 'iptables -t mangle -D %(queue)s -s %(client_ipv4)s -d %(server_ipv4)s -p udp -m multiport --sports %(client_port)s -m multiport --dports %(server_port)s -j MARK --set-mark %(ifindex)s' 

class TSPTunnelConfig(dict):
    def __init__(self,tunnel_manager,flags):
        self.tunnel_manager = tunnel_manager
        if type(flags) != dict:
            raise DDTBError('TSPTunnelConfig requires a dict as parameter')

        for k in TSP_MANDATORY_FLAGS:
            if not flags.has_key(k):
                raise DDTBError('Missing mandatory flag: %s' % k)

        self.update(flags)
        self['server_port'] = tunnel_manager.server_port
        ( self['prefix_network'], self['prefix_mask'] ) = self['prefix'].split('/')

        # Example interface name: c0a00101_1234
        self['interface'] = '%s_%04d' % (
            ''.join(['%02x' % int(x) for x in self['client_ipv4'].split('.')]),
            int(self['client_port'])
        )

        # Ifindex is only initialized when the tunnel is configured or
        # deconfigure is attempted
        self['ifindex'] = None

    def __getattr__(self,attr):
        """
        Wrapper to get dictionary attributes
        """
        try:
            return self[attr]
        except KeyError:
            raise AttributeError('No such TSPTunnelConfig attribute: %s' % attr)

    def __str__(self):
        """
        Returns the interface name 
        """
        return self['interface']

    def get_ifindex(self):
        """
        Return ifindex of tunnel interface, raise ValueError if not configured.
        """
        cmd = ['ip','link','list',self.interface]
        p = Popen(cmd, stdout=PIPE,stderr=PIPE)
        stdout,stderr = p.communicate()
        if stdout.rstrip() == 'Device "%s" does not exist.' % self.interface:
            raise ValueError 
        if p.returncode != 0:
            raise ValueError
        try:
            # Note - we return this as string, not int
            self.ifindex = stdout.split(':')[0]
            return self.ifindex
        except IndexError:
            raise DDTBError('Error splitting ifindex from %s' % stdout)

    def configure(self):
        """
        Configure a TSP tunnel interface and associated iptables and routing
        policy rules for it.
        """

        logs.ddtb.info('Configuring tunnel interface %s' % self.interface)
        for cmd in TSP_TUNNEL_LINK_SETUP_COMMANDS:
            cmd = cmd % self 
#            logs.ddtb.debug('Running cmd: %s' % cmd)
            retval = call(cmd.split())
            if retval != 0:
                raise DDTBError('Error running command %s' % cmd) 
        try:
            self['ifindex'] = '%s' % int(self.get_ifindex())
            self['utun_table'] = '%s' % (int(self.ifindex)+TSP_RTABLE_OFFSET)
        except ValueError:
            logs.ddtb.debug('Interface was not configured: %s' % self.interface)
            raise
 
        for queue in  TSP_MANGLE_QUEUES:
            params = dict(self)
            params['queue'] = queue
            cmd = TSP_MANGLE_COMMAND % params
#            logs.ddtb.debug('Running cmd: %s' % cmd)
            retval = call(cmd.split())
            if retval != 0:
                raise DDTBError('Error running mangle command %s' % cmd)

        for cmd in TSP_TUNNEL_IPTABLES_ROUTING:
            cmd = cmd % self
#            logs.ddtb.debug('Running cmd: %s' % cmd)
            retval = call(cmd.split())
            if retval != 0: 
                raise DDTBError('Error running command: %s' % ' '.join(cmd))

    def deconfigure(self):
        """
        Attempt deconfiguring an TSP tunnel interface
        """

        try:
            self['ifindex'] = '%s' % int(self.get_ifindex())
            self['utun_table'] = '%s' % (int(self.ifindex)+TSP_RTABLE_OFFSET)
        except ValueError:
            logs.ddtb.debug('Interface was not configured: %s' % self.interface)
            return

        for queue in  TSP_MANGLE_QUEUES:
            params = dict(self)
            params['queue'] = queue
            cmd = TSP_UNMANGLE_COMMAND % params
#            logs.ddtb.debug('Running cmd: %s' % cmd)
            retval = call(cmd.split())
            if retval != 0:
                logs.ddtb.error('Error running unmangle command %s' % cmd)

        for cmd in TSP_TUNNEL_CLEANUP_COMMANDS:
            cmd = cmd % self 
#            logs.ddtb.debug('Running cmd: %s' % cmd)
            retval = call(cmd.split())
            if retval != 0:
                logs.ddtb.error('Error running cleanup command %s' % cmd) 

        try:
            self.get_ifindex()
            logs.ddtb.warn('PROBLEM: interface %s was NOT successfully removed.' % (self.interface) )
        except ValueError:
            logs.ddtb.debug('Interface successfully removed: %s' % self.interface)

class TSPTunnelConfigManager(dict):
    def __init__(self,server_ipv4,server_port):
        self.server_ipv4 = server_ipv4
        self.server_port = server_port

    def sync_db_tunnels(self,tunnels):
        """
        Configure tunnels in database to the running system, unless they 
        already exist. 
        """
        for t in tunnels:
            tunnel = TSPTunnelConfig(self,{
                'client_port':   t.client_port,
                'client_ipv4':   t.client_ipv4,
                'client_ipv6':   t.client_ipv6,
                'server_ipv4':   t.server_ipv4,
                'server_ipv6':   t.server_ipv6,
                'prefix':        t.prefix,
            })
            try:
                # Lookup ifindex, expect tunnel already configured if found
                tunnel.get_ifindex()
            except ValueError:
                # Not found, configure
                tunnel.configure()
                logs.ddtb.debug('Restored tunnel: %s' % (tunnel))

            # In case we actually want to use this object as dict:
            #self[tunnel.interface] = tunnel

    def deconfigure_tunnel(self,t_data):
        """
        Clean a tunnel's configuration and remove it from database if needed
        """
        tunnel = TSPTunnelConfig(self,{
                'client_port':   t_data.client_port,
                'client_ipv4':   t_data.client_ipv4,
                'client_ipv6':   t_data.client_ipv6,
                'server_ipv4':   t_data.server_ipv4,
                'server_ipv6':   t_data.server_ipv6,
                'prefix':        t_data.prefix,
        })

        try:
            ifindex = tunnel.get_ifindex()
            tunnel.deconfigure()
        except ValueError:
            logs.ddtb.info('Tunnel interface not configure when removing')

