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
"""
Class to represent IPv4 addresses
"""

# Maximum value available with 32 bits
UINT_MAX = 2**32-1
U128_MAX = 2**128-1

ADDRESS_CLASS_DEFAULT = 'normal'
ADDRESS_CLASS_MAP = {
    'loopback':     ['127.0.0.0/8'],
    'link-local':   ['169.254.0.0/16'],
    'multicast':    ['224.0.0.0/4'],
    'reserved':     ['240.0.0.0/4'],
    'rfc1918':      ['10.0.0.0/8',' 172.16.0.0/12','192.168.0.0/16'],
    'special':      ['0.0.0.0/32','255.255.255.255/32'],
}   

try:
    type(bin)
except NameError:
    def bin(str,pad32bits=True):
        if type(str) not in [int,long]: str = long(str) 
        t={
            '0':'000','1':'001','2':'010','3':'011', 
            '4':'100','5':'101','6':'110','7':'111'
        }
        s=''
        for c in oct(str).rstrip('L')[1:]:
            s+=t[c]
        s = s.lstrip('0')
        if pad32bits and len(s) < 32: s = '0'*(32-len(s)) + s
        return s

def isEthernetMACAddress(value):
    try:
        EthernetMACAddress(value)
    except ValueError:
        return False
    return True

class EthernetMACAddress(object):
    def __init__(self,address):
        try:
            parts = map(lambda x: int(x,16), address.split(':',5))
            for p in parts:
                if p < 0 or p > 255:
                    raise ValueError
        except ValueError:
            raise ValueError('Not a Ethernet MAC address: %s' % address)
        self.address = address

    def __str__(self):
        return self.address

class IPv4Address(object):
    """
    Verify and format IPv4 address given in n.n.n.n/32 format,
    calculate various values for the address.
    
    Raises ValueError if address is not valid.

    Attributes available:
    ipaddress: x.x.x.x address
    bitmask:   bitmask (0-32) 
    netmask:   netmask in x.x.x.x format
    inverted_netmask: netmask in x.x.x.x, inverted (cisco style)
    network:   network address, raises ValueError for /32 addresses 
    broadcast: broadcast address, raises ValueError for /32 addresses
    first:     return first host address in network
    last:      return last host address in network

    Internally available:
    address:   IPv4 address as long integer
    mask:      IPv4 netmask as long integer
    """
    def __init__(self,address,netmask=None,oldformat=False):
        """
        Parameters:
        address: dot format address as in inet, or long integer
        netmask: netmask in dot format or long integer
        """ 
        self.oldformat = oldformat
        if type(address) in [int,long]:
            ip = address
            mask = 32
        else:
            try:
                (ip,mask) = address.split('/',1)
            except ValueError:
                ip = address
                if netmask:
                    try:
                        netmask = self.__parseaddress__(netmask)
                        if netmask == UINT_MAX:
                            mask = 32
                        else:
                            if bin(UINT_MAX &~ netmask)[2:].count('0')>0: 
                                raise ValueError
                            mask = 32-len(bin(UINT_MAX &~ netmask))+2
                    except ValueError:
                        raise ValueError('Invalid netmask value: %s' % netmask)
                elif self.oldformat:
                    if address.count('.') == 2:
                        mask = 24
                    elif address.count('.') == 1:
                        mask = 16
                    elif address.count('.') == 0:
                        mask = 8
                    else:
                        mask = 32
                else:
                    mask = 32
        try:
            mask = int(mask)
            if mask not in range(0,33):
                raise ValueError
            self.mask = UINT_MAX ^ (2**(32-mask)-1)
        except ValueError:
            raise ValueError('Invalid netmask: %s' % mask)
        try:
            self.address = self.__parseaddress__(ip)
        except ValueError:
            raise ValueError('Invalid address: %s' % address)

    def __parsenumber__(self,value):
        """
        Parses decimal, octal, hex value from string
        """
        value = str(value)
        if value[:2] == '0x':
            return int(value,16)
        elif value[:1] == '0':
            return int(value,8)
        else:
            return int(value)

    def __parseaddress__(self,value):
        """
        Try to parse an ip-address from various crazy formats defined
        for IP addresses. Of course, sane people would only pass normal
        addresses to us but who knows...
        """
        value = str(value)
        if value.count('.') == 3:
            dotted = []
            parts = value.split('.')
            for i,p in enumerate(parts):
                p = self.__parsenumber__(p)
                if p not in range(0,256):
                    raise ValueError
                dotted.append(p)

            return reduce(lambda x,y:x+y,[
                (dotted[0]<<24), (dotted[1]<<16), (dotted[2]<<8),(dotted[3]),
            ])
        elif value.count('.') == 2:
            dotted = []
            parts = value.split('.')
            for i,p in enumerate(parts):
                p = self.__parsenumber__(p)
                if not self.oldformat:
                    if i>2 and (p<0 or p>2**8):
                        raise ValueError
                    elif i==2 and (p<0 or p>2**16):
                        raise ValueError
                else:
                    if p<0 or p>2**8:
                        raise ValueError
                dotted.append(p)     
            if not self.oldformat:
                return reduce(lambda x,y:x+y,[
                    (dotted[0]<<24),(dotted[1]<<16),(dotted[2])
                ])
            else:
                return reduce(lambda x,y:x+y,[
                    (dotted[0]<<24),(dotted[1]<<16),(dotted[2]<<8)
                ])
        elif value.count('.') == 1:
            dotted = []
            parts = value.split('.')
            for i,p in enumerate(parts):
                p = self.__parsenumber__(p)
                if not self.oldformat:
                    if i==0 and (p<0 or p>2**8):
                        raise ValueError
                    elif i==1 and (p<0 or p>2**24):
                        raise ValueError
                else:
                    if (p<0 or p>2**8):
                        raise ValueError
                dotted.append(p)
            if not self.oldformat:
                return reduce(lambda x,y:x+y,[(dotted[0]<<24),(dotted[1])])
            else:
                return reduce(lambda x,y:x+y,[
                    (dotted[0]<<24),(dotted[1]<<16)
                ])
        else:
            if not self.oldformat:
                return self.__parsenumber__(value)
            else:
                return self.__parsenumber__(value)<<24
        raise ValueError

    def __str__(self):
        """
        Returns a CIDR address formatted string for this address
        """
        return '%s/%s' % (self.ipaddress,self.bitmask)

    def __len__(self):
        """
        Return number of hosts possible in the network, excluding network 
        address and broadcast address: NOT reserving a gateway address!
        """
        if self.bitmask > 30:
            return 1
        elif self.bitmask == 30:
            return 2
        first = (self.address & self.mask)+1
        last  = (self.address & self.mask) + (UINT_MAX &~ self.mask)
        return last-first

    def __long__(self):
        """
        Return the integer representation for this IPv4 address
        """
        return self.address

    def __long2address__(self,value):
        """
        Convert a long integer back to n.n.n.n format
        """
        parts = []
        for i in range(0,4):
            p = str((value &~ (UINT_MAX^2**(32-i*8)-1)) >> (32-(i+1)*8))
            parts.append(p)
        return '.'.join(parts)

    def __addressclass__(self):
        for aclass,networks in ADDRESS_CLASS_MAP.items():
            for net in networks:
                if IPv4Address(net).addressInNetwork(self.ipaddress):
                    return aclass
        return ADDRESS_CLASS_DEFAULT 

    def __getattr__(self,item):
        """
        Return various address and network related attributes 
        """
        if item == 'ipaddress': 
            return self.__long2address__(self.address) 
        if item == 'bitstring':
            return '0x%x' % self.address
        if item == 'addressclass':
            return self.__addressclass__()
        if item == 'bitmask': 
            if self.mask == UINT_MAX: return 32
            return 32-len(bin(UINT_MAX &~ self.mask))+2
        if item == 'netmask': 
            return self.__long2address__(self.mask) 
        if item == 'inverted_netmask': 
            return self.__long2address__(UINT_MAX ^ self.mask) 
        if item == 'network':
            if self.bitmask == 32:
                self.ipaddress
            return self.__long2address__(self.address & self.mask)
        if item == 'broadcast':
            if self.bitmask == 32:
                raise ValueError('No broadcast address for /32 address')
            return self.__long2address__(
                (self.address & self.mask) + (UINT_MAX &~ self.mask)
            )
        if item == 'first':
            if self.bitmask == 32:
                return self.ipaddress
            if self.bitmask == 31:
                return self.__long2address__(self.address & self.mask)
            return IPv4Address((self.address & self.mask)+1)
        if item == 'last':
            if self.bitmask == 32:
                return self.ipaddress
            if self.bitmask == 31:
                return self.__long2address__((self.address & self.mask)+1)
            return IPv4Address(
                (self.address & self.mask) + (UINT_MAX &~ self.mask) - 1
            )
        if item == 'next':
            address = self.address+1
            if address >= UINT_MAX:
                return None
            return IPv4Address(address)
        if item == 'prev':
            address = self.address-1
            if address < 0:
                return None
            return IPv4Address(address)
        if item == 'next_network':
            address = self.address+2**(32-self.bitmask)
            if address >= UINT_MAX:
                return None
            return IPv4Address('%s/%s' % (address,self.bitmask))
        if item == 'previous_network':
            address = self.address-2**(32-self.bitmask)
            if address < 0:
                return None
            return IPv4Address('%s/%s' % (address,self.bitmask))
        if item == 'dns_reverse_ptr':
            return '%s.in-addr.arpa.' % '.'.join(reversed(self.ipaddress.split('.')))
        raise AttributeError('No such IPv4Address attribute: %s' % item)

    def __getitem__(self,item):
        try:
            return getattr(self,item)
        except TypeError:
            print type(item)
            raise AttributeError
        except AttributeError,e:
            raise KeyError('No such IPv4Address item: %s' % item)

    def addressInNetwork(self,address):
        """
        Tests if given IPv4 address is in range of this network, 
        including network and broadcast addresses
        """
        ip = IPv4Address(address)
        if self.bitmask == 0:
            return True
        if self.bitmask == 32 and ip.address != self.address:
            return False
        else:
            first = self.address & self.mask
            last = (self.address & self.mask) + (UINT_MAX &~ self.mask) 
            if ip.address < first or ip.address > last: 
                return False
        return True

    def hostInNetwork(self,address):
        """
        Tests if given IPv4 address is in range of this network, 
        excluding network and broadcast addresses
        """
        ip = IPv4Address(address)
        if self.bitmask == 0:
            return True
        if self.bitmask == 32 and ip.address != self.address:
            return False
        if self.bitmask == 31:
            first = self.address & self.mask
            if ip.address < first or ip.address > first+1:
                return False
        else:
            first = self.address & self.mask
            last = (self.address & self.mask) + (UINT_MAX &~ self.mask) 
            if ip.address <= first or ip.address >= last: 
                return False
        return True

    def split(self,bitmask,maxcount=None):
        if self.bitmask >= 30:
            raise ValueError("Can't split network with mask %s" % self.bitmask)
        try:
            bitmask = int(bitmask)
            if bitmask < 1 or bitmask > 30:
                raise ValueError
        except ValueError:  
            raise ValueError('Invalid split mask: %s' % bitmask)
        if bitmask <= self.bitmask:
            raise ValueError('Split mask must be larger than network mask %s' % self.bitmask)
        networks = [IPv4Address('%s/%s' % (self.ipaddress,bitmask))]
        last = self.last
        next = IPv4Address('%s/%s' % (self.address+2**(32-bitmask),bitmask))
        while True:
            if maxcount is not None and maxcount < len(networks):
                break
            networks.append(next)
            if next.last.address >= last.address:
                break
            next = IPv4Address('%s/%s' % (next.address+2**(32-bitmask),bitmask))
        return networks 

    def dns_reverse_origin(self):
        if self.bitmask >= 24:
            return '%s.in-addr.arpa.' % '.'.join(reversed(self.ipaddress.split('.')[:3]))
        elif self.bitmask >= 16:
            return '%s.in-addr.arpa.' % '.'.join(reversed(self.ipaddress.split('.')[:2]))
        elif self.bitmask >= 8: 
            return '%s.in-addr.arpa.' % self.ipaddress.split('.')[0]
        else:
            raise ValueError("Can't create reverse origin for mask %s" % self.bitmask)

class IPv4AddressRange(object):
    """
    Defines a IPv4 address range, which you can:
    - check length of arbitrary range quickly
    - check if given address is in range
    - iterate to get IPv4Address objects for each address in range
    """

    __slots__ = ['__next','first','last']

    def __init__(self,first,last):
        """
        First address and last address must be valid IPv4 addresses, and first 
        address must be smaller than last address.

        Any netmask given to the first or last address is ignored, i.e. 
        IPv4AddressRange('192.168.0.0/24','192.168.0.10/8') returns range
        192.168.0.0-192.168.0.10

        Raises ValueError if the addresses can not be parsed or if the range is
        invalid.
        """
        self.__next = 0
        self.first = IPv4Address(first)
        self.last = IPv4Address(last)

        if self.last.address<self.first.address:
            raise ValueError('Invalid range: last address is smaller than first address')

    def __str__(self):
        return '%s-%s' % (self.first.ipaddress,self.last.ipaddress)

    def __len__(self):
        """
        Returns number of addresses in the range, including first and last address
        """
        return self.last.address - self.first.address + 1

    def __iter__(self):
        return self

    def next(self):
        if self.first.address+self.__next>self.last.address:
            raise StopIteration
        address = IPv4Address(self.first.address+self.__next)
        self.__next += 1
        return address

    def contains(self,item):
        """
        Check if given address is in the range, including first and last
        address. 
        
        The item must be IPv4Address object.
        """
        if item.address < self.first.address or item.address > self.last.address:
            return False
        return True

class IPv6Address(dict):
    def __init__(self,value):
        try:
            address,bitmask = value.split('/')
        except ValueError:
            address = value
            bitmask = 128
        try:
            bitmask = int(bitmask)
            if int(bitmask) < 0 or int(bitmask) > 128:  
                raise ValueError
        except ValueError:
            raise ValueError('Invalid IPv6 mask %s' % bitmask)
        try:
            subs = address.split(':')
            if len(subs) == 1:
                raise ValueError
            if subs.count('') > 0:
                pad = subs.index('')
                if subs[pad+1] == '': 
                    subs.pop(pad+1)
                if subs[0] != '':
                    start = ''.join(['%04x' % int(s,16) for s in subs[:subs.index('')]])
                    end = ''.join(['%04x' % int(s,16) for s in subs[subs.index('')+1:]])
                    hex_bitstring = '0x%s%s%s' % (start,'0'*(32-len(start)-len(end)),end)
                else:
                    end = ''.join(['%04x' % int(s,16) for s in subs[1:]])
                    hex_bitstring = '0x%s%s' % ('0'*(32-len(end)),end)
            else:
                hex_bitstring = ''.join(['%04x' % int(s,16) for s in subs])

            addrval = long(hex_bitstring,16)
            network_bitstring = '0x%032x' % (
                addrval &~ ( U128_MAX & (2**(128-bitmask)-1) )
            )

            # Correctly calculate network from  
            nbs = [int(network_bitstring[2:][i:i+4],16) for i in range(0,32,4)]
            while nbs[-1] == 0: nbs = nbs[:-1]
            network = '%s::/%s' % (':'.join(['%x' % n for n in nbs]),bitmask)

            try:
                revnibbles = '.'.join(
                    reversed([hex_bitstring[2+x] for x in range(0,(bitmask/4))])
                )
            except IndexError:
                raise ValueError('Error splitting hexstring for revnibbles')
        except ValueError,e:
            raise ValueError('Invalid IPv6 address: %s: %s' % (value,e))
        
        if not address.endswith('::'):
            self['type'] = 'address'
        else:
            self['type'] = 'subnet'
        self.update({
            'address':  address,
            'bitstring': hex_bitstring,
            'bitmask': bitmask,
            'network': network,
            'network_bitstring': network_bitstring,
            'revnibbles_int': '%s.ip6.int.' % revnibbles,
            'revnibbles_arpa': '%s.ip6.arpa.' % revnibbles,
        })

    def __repr__(self):
        return '%s/%s' % (self.address,self.bitmask)

    def __addrfmt__(self,address,mask):
        s = '%032x' % address
        value = ['%x' % int(s[i:i+4],16) for i in range(0,32,4)] 
        # Find the longest chain of 0's to truncate 
        longest = 0 
        index = None
        i = 0
        while i < len(value):
            if int(value[i],16) != 0:
                i+=1
                continue 
            zeros = 0
            for v in value[i:]:
                if int(v,16) != 0:
                    break
                zeros += 1
            if zeros > longest: 
                longest = zeros
                index = i
            i += zeros
        if index is not None:   
            del(value[index:index+longest])
            value.insert(index,'')

        value = ':'.join(value)
        if value.startswith(':'):
            value = ':'+value
        if value.endswith(':'):
            value += ':'
        return '%s/%s' % (value,mask)

    def __getattr__(self,attr):
        if attr == 'first':
            return IPv6Address(
                self.__addrfmt__(
                    int(self.network_bitstring,16)+1,
                    self.bitmask
                )
            )
        if attr == 'last':
            return IPv6Address(
                self.__addrfmt__(
                    int(self.network_bitstring,16)+2**(128-self.bitmask)-1,
                    self.bitmask
                )
            )
        if attr in ['next']:
            next = int(self.bitstring,16) + 1
            if next > U128_MAX:
                return None
            return IPv6Address(self.__addrfmt__(next,self.bitmask))
        if attr in ['previous']:
            next = int(self.bitstring,16) - 1
            if next < 0:
                return None
            return IPv6Address(self.__addrfmt__(next,self.bitmask))
        if attr in ['next_network']:
            network = int(self.network_bitstring,16) + 2**(128-self.bitmask)
            if network >= U128_MAX:
                return None
            return IPv6Address(self.__addrfmt__(network,self.bitmask))
        if attr in ['previous_network']:
            network = int(self.network_bitstring,16) - 2**(128-self.bitmask)
            if network < 0:
                return None
            return IPv6Address(self.__addrfmt__(network,self.bitmask))
        try:
            return self[attr]
        except KeyError:
            raise AttributeError('No such IPv6Address attribute: %s' % attr)

    def hostInNetwork(self,value):
        if type(value) is not IPv6Address:
            try:
                value = IPv6Address(value)
            except ValueError,e:
                raise ValueError('Invalid IPv6Address: %s' % value)
        value = int(value.bitstring,16)
        first = int(self.network_bitstring,16)+1
        last = int(self.network_bitstring,16)+2**(128-self.bitmask)-1
        if value < first or value > last:
            return False
        return True

class SubnetPrefixIterator(object):
    def __init__(self,address,splitmask):
        try:
            splitmask = int(splitmask)
        except ValueError:  
            raise ValueError('Invalid splitmask')
        try:
            self.address = IPv4Address(address)
            self.last = self.address.last.address
        except ValueError:  
            try:
                self.address = IPv6Address(address)
                self.last = long(self.address.last.bitstring,16)
            except ValueError:
                raise ValueError('Not valid IPv4 or IPv6 address: %s' % address)
        if self.address.bitmask >= splitmask:
            raise ValueError('Split mask must be smaller than network mask')
        if type(self.address) == IPv4Address:
            self.first = IPv4Address('%s/%s' % (self.address.network,splitmask))
        if type(self.address) == IPv6Address:
            a = self.address.network.split('/')[0] 
            self.first = IPv6Address('%s/%s' % (a,splitmask))
        self.__next = self.first

    def __iter__(self):
        return self

    def next(self):
        try:
            if type(self.__next) == IPv4Address:
                if self.__next is None:
                    raise StopIteration
                entry = self.__next
                if self.address.last.address <= entry.first.address:
                    raise StopIteration
                self.__next = entry.next_network
            if type(self.__next) == IPv6Address:
                if self.__next is None:
                    raise StopIteration
                entry = self.__next
                entry_first = long(entry.first.bitstring,16)
                if self.last <= entry_first:
                    raise StopIteration
                self.__next = entry.next_network
        except StopIteration:
            self.__next = self.first
            raise StopIteration
        return entry 

