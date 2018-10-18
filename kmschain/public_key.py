#
import binascii
import proxylib

#
from .proxy_lib import ProxyLib
from .capsule import Capsule


#
class PublicKey(ProxyLib):
    """
    PublicKey object, which is Python implementation of
    extended C/C++ library interface
    """

    def __init__(self, cm):
        self.cm = cm
        super().__init__()

    def to_bytes(self):
        """
        Convert Public Key object into byte array

        :param no:
        :return byte array:
        """

        return binascii.hexlify(proxylib.proxylib_public_key_to_bytes(self.get_pointer()))

    def from_bytes(self, data):
        """
        Get Public Key from given byte array.

        :param data: byte array
        :return: no
        """

        self.set_pointer(proxylib.proxylib_public_key_from_bytes(self.get_pointer(), binascii.unhexlify(data)))

    def encapsulation(self):
        """
        Making encapsulation and getting Capsule with symmetric key

        :param no:
        :return capsule and symmetric key

        """
        capsule = Capsule(ProxyLib())
        capsule_pointer, symmetric_key = proxylib.proxylib_encapsulate(self.cm.get_pointer(), self.get_pointer())
        capsule.set_pointer(capsule_pointer)
        return capsule, symmetric_key
