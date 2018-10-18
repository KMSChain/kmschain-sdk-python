import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

#
from unittest import TestCase


#
class TestProxyLib(TestCase):
    def setUp(self):
        #
        super(TestProxyLib, self).setUp()
