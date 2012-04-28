 # Copyright (C) CITC, Communications and Information Technology Commission,
 # Kingdom of Saudi Arabia.
 #
 # Developed by CITC Tunnel Broker team, tunnelbroker@citc.gov.sa.
 #
 # This software is released to public domain under GNU General Public License
 # version 2, June 1991 or any later. Please see file 'LICENSE' in source code
 # repository root.

"""
DDTB tunnel broker server implementation. 
"""

__import__('pkg_resources').declare_namespace(__name__)
__all__ = [
    'address','auth','config','ddtblog','model','prefix','session','tunnel','crypto'
]

class DDTBError(Exception):
    """
    Generic errors raised by DDTB tunnel broker
    """
    def __str__(self):
        return self.args[0]

