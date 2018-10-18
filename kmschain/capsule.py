#
import binascii
import proxylib

#
from .proxy_lib import ProxyLib


#
class Capsule(ProxyLib):
    """
    Cryptographic capsule referenced from C/C++ library implementation.
    """
    def __init__(self, cm):
        self.cm = cm
        super().__init__()

    def to_bytes(self):
        """
        Convert Capsule object into byte array

        :param no:
        :return byte array:
        """
        return binascii.hexlify(proxylib.proxylib_capsule_to_bytes(self.get_pointer()))

    def from_bytes(self, data):
        """
        Get capsule key from given byte array.

        :param data: byte array
        :return: no
        """

        self.set_pointer(proxylib.proxylib_capsule_from_bytes(self.get_pointer(), binascii.unhexlify(data)))
