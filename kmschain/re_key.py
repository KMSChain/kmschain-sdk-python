#
import binascii
import proxylib

#
from .proxy_lib import ProxyLib
from .capsule import Capsule


#
class ReEncryptionKey(ProxyLib):
    
    def __init__(self, cm):
        self.cm = cm
        super().__init__()

    def re_encryption(self, capsule):
        """
        Running re-encryption for given capsule and returning re-encrypted capsule

        :param capsule: capsule obj
        :return recapsule: re-encrypted capsule
        """

        recapsule = Capsule()
        capsule_pointer = cryptomagic.cryptomagic_get_re_encryption_capsule(self.cm.get_pointer(), capsule.get_pointer(), self.get_pointer())
        recapsule.set_pointer(capsule_pointer)
        return recapsule

    def to_bytes(self):
        """
        Convert Re-Encryption Key object into byte array

        :param no:
        :return byte array:
        """

        return binascii.hexlify(proxylib.proxylib_re_encryption_to_bytes(self.get_pointer()))

    def from_bytes(self, data):
        """
        Get Re-Encryption key from given byte array.

        :param data: byte array
        :return: no
        """

        self.set_pointer(proxylib.proxylib_get_re_encryption_from_bytes(self.get_pointer(), binascii.unhexlify(data)))
