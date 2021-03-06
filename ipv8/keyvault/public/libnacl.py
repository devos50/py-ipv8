from .. import libnacl
from ...keyvault.keys import PublicKey


class LibNaCLPK(PublicKey):
    """
    A LibNaCL implementation of a public key.
    """

    def __init__(self, binarykey="", pk=None, hex_vk=None):
        """
        Create a new LibNaCL public key. Optionally load it from a string representation or
        using a public key and verification key.

        :param binarykey: load the pk from this string (see key_to_bin())
        :param pk: the libnacl public key to use in byte format
        :param hex_vk: a verification key in hex format
        """
        # Load the key, if specified
        if binarykey:
            pk, vk = binarykey[:libnacl.crypto_box_SECRETKEYBYTES],\
                     binarykey[libnacl.crypto_box_SECRETKEYBYTES:
                               libnacl.crypto_box_SECRETKEYBYTES + libnacl.crypto_sign_SEEDBYTES]
            hex_vk = libnacl.encode.hex_encode(vk)
        # Construct the public key and verifier objects
        self.key = libnacl.public.PublicKey(pk)
        self.veri = libnacl.sign.Verifier(hex_vk)

    def verify(self, signature, msg):
        """
        Verify whether a given signature is correct for a message.

        :param signature: the given signature
        :param msg: the given message
        """
        return self.veri.verify(signature + msg)

    def key_to_bin(self):
        """
        Get the string representation of this key.
        """
        return "LibNaCLPK:" + self.key.pk + self.veri.vk

    def get_signature_length(self):
        """
        Returns the length, in bytes, of each signature made using EC.
        """
        return libnacl.crypto_sign_BYTES
