#
from .proxy_lib import ProxyLib
from private_key import PrivateKey
from public_key import PublicKey
from capsule import Capsule
from re_key import ReEncryptionKey


#
class KMSChain(ProxyLib):
    """
    Main KmsChain structure for having API functions referenced from it.
    """

    def generate(self):
        """
        Generate Private Key

        :param no
        :return private key:
        """
        sk = PrivateKey(ProxyLib())
        sk.generate()
        return sk

    def public_key(self, sk):
        pk = sk.get_public_key()
        return pk

    def generate_re_key(self, sk, pk):
        rk = sk.generate_re_encryption_key(pk)
        return rk

    def decapsulate(self, sk, capsule):
        return sk.decapsulation(capsule)

    def encapsulate(self, pk):
        return pk.encapsulation()

    def re_encrypt(self, rk, capsule):
        return rk.re_encryption(capsule)


    def private_key_from_bytes(self, data):
        """
        Get private key from given byte array.

        :param data: byte array
        :return: private key
        """
        sk = PrivateKey(ProxyLib())
        sk.set_pointer(self.get_pointer())
        sk.from_bytes(data)
        return sk

    def public_key_from_bytes(self, data):
        """
        Get public key from given byte array.

        :param data: byte array
        :return: public key
        """
        pk = PublicKey(ProxyLib())
        pk.set_pointer(self.get_pointer())
        pk.from_bytes(data)
        return pk

    def capsule_from_bytes(self, data):
        """
        Get capsule key from given byte array.

        :param data: byte array
        :return: capsule
        """
        cs = Capsule(ProxyLib())
        cs.set_pointer(self.get_pointer())
        cs.from_bytes(data)
        return cs

    def re_encryption_key_from_bytes(self, data):
        """
        Get re-encryption key from given byte array.

        :param data: byte array
        :return: re-encryption key
        """
        rk = ReEncryptionKey(ProxyLib())
        rk.set_pointer(self.get_pointer())
        rk.from_bytes(data)
        return rk
