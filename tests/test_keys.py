#
import os

#
from proxylib_test import TestProxyLib

import kmschain
from kmschain.kmschain import KMSChain


#
class KeyFromToBytes(TestProxyLib):
    #
    def setUp(self):
        super(KeyFromToBytes, self).setUp()

    #
    def test_public_key_from_to_bytes(self):
        KmsChain = KMSChain()
        sk = KmsChain.generate()

        pk_1 = KmsChain.public_key(sk)

        pk_data_1 = pk_1.to_bytes()
        print("\nPK1 {}\n".format(pk_data_1))
        pk_2 = KmsChain.public_key_from_bytes(pk_data_1)

        pk_data_2 = pk_2.to_bytes()
        print("\nPK2 {}\n".format(pk_data_2))

        self.assertEqual(pk_data_1, pk_data_2)

    def test_private_key_from_to_bytes(self):
        KmsChain = KMSChain()
        sk_1 = KmsChain.generate()

        sk_data_1 = sk_1.to_bytes()
        sk_2 = KmsChain.private_key_from_bytes(sk_data_1)

        sk_data_2 = sk_2.to_bytes()
        self.assertEqual(sk_data_1, sk_data_2)
