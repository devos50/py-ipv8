from socket import inet_aton
from struct import pack, unpack
from time import time

from .keyvault.crypto import ECCrypto
from .keyvault.keys import Key


class Peer(object):

    def __init__(self, key, address=("0.0.0.0", 0), intro=True):
        """
        Create a new Peer.

        :param key: the peer's Key (mostly public) or public key bin
        :param lan_address: the (IP, port) tuple of this peer on its LAN
        :param wan_address: the (IP, port) tuple of this peer on its WAN
        :param intro: is this peer suggested to us (otherwise it contacted us)
        """
        if not isinstance(key, Key):
            self.key = ECCrypto().key_from_public_bin(key)
        else:
            self.key = key
        self.address = address
        self.last_response = 0 if intro else time()
        self._lamport_timestamp = 0
        self.computed_mid = None

    def update_clock(self, timestamp):
        """
        Update the Lamport timestamp for this peer. The Lamport clock dictates that the current timestamp is
        the maximum of the last known and the most recently delivered timestamp. This is useful when messages
        are delivered asynchronously.

        We also keep a real time timestamp of the last received message for timeout purposes.

        :param timestamp: a received timestamp
        """
        self._lamport_timestamp = max(self._lamport_timestamp, timestamp)
        self.last_response = time() # This is in seconds since the epoch

    def get_lamport_timestamp(self):
        return self._lamport_timestamp

    @property
    def mid(self):
        if not self.computed_mid:
            self.computed_mid = self.key.key_to_hash()
        return self.computed_mid

    @property
    def public_key(self):
        return self.key.pub()

    def __hash__(self):
        address = inet_aton(self.address[0]) + pack(">I", self.address[1])
        mid = self.mid[0:8]
        out = ""
        for i in range(8):
            out += chr(ord(mid[i]) ^ ord(address[i]))
        return unpack(">Q", out)[0]

    def __eq__(self, other):
        if not isinstance(other, Peer):
            return False
        return (self.public_key.key_to_bin() == other.public_key.key_to_bin()) and (self.address == other.address)

    def __str__(self):
        return 'Peer<%s:%d, %s>' % (self.address + (self.mid.encode('base64')[:-1], ))
