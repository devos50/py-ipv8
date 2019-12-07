from __future__ import absolute_import

from enum import Enum


class SecurityMode(Enum):
    """
    Implementations of security implementations of Noodle.
    """
    VANILLA = 1
    AUDIT = 2


class NoodleSettings(object):
    """
    Settings for the Noodle protocol.
    """

    def __init__(self):
        # Is the node hiding own blocks?
        self.is_hiding = False

        # TTL for informed information dissemination, depends on the topology
        self.ttl = 3

        # Use informed broadcast
        self.use_informed_broadcast = False

        # Sync round time in seconds
        self.sync_time = 1

        # Security mode
        self.security_mode = SecurityMode.VANILLA

        # Security epsilon
        self.com_size = 5

        # Tolerated inconsistency risk
        self.risk = 0.5
