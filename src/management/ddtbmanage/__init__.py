"""
DDTB tunnel broker server implementation.
"""

__import__('pkg_resources').declare_namespace(__name__)
__all__ = ['address','config']

class DDTBError(Exception):
    """
    Generic errors raised by DDTB tunnel broker
    """
    def __str__(self):
        return self.args[0]
