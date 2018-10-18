#
import proxylib


#
class ProxyLib:
    """
    Main Crypto operations structure, which is a Python implementation
    of existing C/C++ library interface
    """

    def __init__(self):
        """
        Making new ProxyLib root object to perform cryptographic operations.

        :param no:
        """
        self.__pointer = proxylib.proxylib_new()

    def get_pointer(self):
        return self.__pointer

    def set_pointer(self, pointer):
        self.__pointer = pointer
