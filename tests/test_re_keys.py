#
import os

#
from proxylib_test import TestProxyLib

import kmschain
from kmschain.kmschain import KMSChain

#
class ReKeyFromToBytes(TestProxyLib):
    #
    def setUp(self):
        super(ReKeyFromToBytes, self).setUp()

    #
    def test_re_key_from_to_bytes(self):
        KmsChain = KMSChain()
        skA = KmsChain.generate()
        skB = KmsChain.generate()
        pkB = KmsChain.public_key(skB)

        rkAB_1 = KmsChain.generate_re_key(skA, pkB)

        rkAB_1_data = rkAB_1.to_bytes()

        rkAB_2 = KmsChain.re_encryption_key_from_bytes(rkAB_1_data)

        rkAB_2_data = rkAB_2.to_bytes()

        self.assertEqual(rkAB_1_data, rkAB_2_data)
