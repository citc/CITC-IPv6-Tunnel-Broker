## Copyright (c) 2010, Coptix, Inc.  All rights reserved.
## See the LICENSE file for license terms and warranty disclaimer.

"""prelude -- extra builtins"""

from __future__ import absolute_import
import os, logging

__all__ = ('log', )

log = logging.getLogger(os.path.basename(os.path.dirname(__file__)))
log.addHandler(logging.StreamHandler())
