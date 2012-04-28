#!/usr/bin/python

 # Copyright (C) CITC, Communications and Information Technology Commission,
 # Kingdom of Saudi Arabia.
 #
 # Developed by CITC Tunnel Broker team, tunnelbroker@citc.gov.sa.
 #
 # This software is released to public domain under GNU General Public License
 # version 2, June 1991 or any later. Please see file 'LICENSE' in source code
 # repository root.

import os,sys,time,random,socket,subprocess
from storm.locals import *

from ddtb import DDTBError
from ddtb.config import DDTBConfig
from ddtb.database import DDTBDatabase
from address import IPv4Address,IPv6Address,SubnetPrefixIterator

DEFAULT_STALE_CLEANUP_TIME = 600

class CustomerAllocation(dict):
    """
    Class to wrap the address prefix and mask details to a nicely formatted
    accessor. Does not actually do anything for the details, just gives them
    nicely formatted for other uses.
    """
    def __init__(self,pool,address,user_id=None):
        self['user_id']     = user_id 
        self['prefix_type'] = 'TSP'
        self['network']     = address.network
        self['bitstring']   = address.network_bitstring[2:]
        self['mask']        = int(address.bitmask)
        self['server_ipv6'] = address.first
        self['client_ipv6'] = address.first.next

    def __getattr__(self,attr):
        try:
            return self[attr]
        except KeyError:
            raise AttributeError('No such CustomerAllocation attr %s' % attr)

    def __str__(self):
        return '%s (%d mask)' % ( self.network, self.mask )

class CustomerAddressPool(dict):
    def __init__(self,database,address,allocation_size):
        """
        Class to iterate possible address prefixes in given address pools, 
        looking for unallocated pool.
        """
        self.database = database
        try:
            self.address = address
            self.prefixes = SubnetPrefixIterator(address,allocation_size)
            self.allocation_size = allocation_size
        except ValueError,e:    
            raise DDTBError('Error creating address pool: %s' % e)

        self.update_db_prefix_cache()

    def update_db_prefix_cache(self):
        """
        Update current prefixes from database to local cache
        """
        self.update({})
        for allocation in self.database.prefixes():
            ca = CustomerAllocation(self, 
                IPv6Address(allocation.prefix),
                user_id=allocation.client_id
            )
            self[allocation.prefix] = ca
        logs.ddtb.debug('Loaded %d prefixes from DB' % len(self.keys()))

    def find_allocation(self,user_id):
        """
        Returns user's prefix allocations from database, returning it in a 
        CustomerAllocation object.
        """
        prefixes = []
        for p in self.database.prefixes(user_id=user_id):
            prefixes.append(
                CustomerAllocation(self,
                IPv6Address(p.prefix),
                user_id)
            )
        return prefixes 

    def find_next(self,user_id=None):
        """
        Returns next prefix from this pool
        """ 
        # TODO - think when to actually update this from DB, not every time.
        # In general, this may need lots of refactoring!
        self.update_db_prefix_cache()
        while True:
            try:
                ca = CustomerAllocation(self,self.prefixes.next(),user_id) 
                try:
                    existing = self[ca.network]
                    if existing.user_id == user_id:
                        # Return user's network
                        return ca
                    else:
                        # Allocated to someone else
                        continue
                except KeyError:
                    self.database.register_prefix(user_id,ca)
                    self[ca.network] = ca
                    return ca
            except StopIteration:
                raise DDTBError('No more Ipv6 prefixes in %s' % self.address)

