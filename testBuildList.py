#!/usr/bin/python3

# testBuildList.py

import base64
import hashlib
import os
import time
import unittest
from Crypto.PublicKey import RSA

from rnglib import SimpleRNG
from xlattice.util import timestamp
from buildList import *


class TestBuildList (unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    # utility functions #############################################

    # actual unit tests #############################################

    def expectException(self, pathToDir):
        try:
            BuildList.createFromFileSystem('anything', pathToDir, None)
            self.fail("accepted '%s' as pathToDir")
        except RuntimeError as e:
            pass
        except Exception as e2:
            self.fail("unexpected exception %s" % e2)

    def doTestBadParts(self):
        # we object to absolute paths
        self.expectException('/')
        self.expectException('/abc')

        # and we objected to embedded . and ..
        self.expectException('.')
        self.expectException('..')
        self.expectException('./')
        self.expectException('..//')
        self.expectException('./a')
        self.expectException('../b')
        self.expectException('a/.')
        self.expectException('b/..')
        self.expectException('a/./b')
        self.expectException('b/../c')

    def doBuildTest(self, title, usingSHA1):
        skPriv = RSA.generate(1024)
        sk = skPriv.publickey()

        pathToData = os.path.join('example', 'dataDir')
        bl = BuildList.createFromFileSystem(
            'a trial list', pathToData, sk, usingSHA1)

        # check properties ------------------------------------------
        self.assertEqual(bl.title, 'a trial list')
        self.assertEqual(bl.publicKey, sk)
        self.assertEqual(bl.timestamp, timestamp(0))
        self.assertEqual(bl.usingSHA1, usingSHA1)

        # check sign() and verify() ---------------------------------

        self.assertEqual(bl, bl)
        self.assertFalse(bl.verify())   # not signed yet

        bl.sign(skPriv)
        sig = bl.digSig                 # this is the base64-encoded value
        self.assertTrue(sig is not None)
        self.assertTrue(bl.verify())    # it has been signed

        # equality, serialization, deserialization ------------------
        self.assertEqual(bl, bl)
        s = bl.toString()
        # DEBUG
        #print("SIGNED BUILD LIST:\n%s" % s)
        # END
        bl2 = BuildList.parse(s, usingSHA1)
        s2 = bl2.toString()
        self.assertEqual(s, s2)
        self.assertEqual(bl, bl)  # same list, but signed now
        self.assertEqual(bl, bl2)

    def testBuildList(self):
        self.doTestBadParts()
        self.doBuildTest('SHA1 test', True)
        self.doBuildTest('SHA2 test', False)

if __name__ == '__main__':
    unittest.main()
