#!/usr/bin/env python3

# testBuildList.py

import os
import sys
import time
import unittest
from Crypto.PublicKey import RSA

from argparse import ArgumentParser

from rnglib import SimpleRNG
from xlattice import Q, check_using_sha
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
        # DEBUG
        # print("ENTERING expectException, path = '%s'" % pathToDir)
        # END
        try:
            BuildList.create_from_file_system('anything', pathToDir, None)
            self.fail("accepted '%s' as pathToDir")
        except RuntimeError as e:
            pass
        except Exception as e2:
            self.fail("unexpected exception %s" % e2)

#   def doTestBadParts(self):
#       # we object to absolute paths
#       self.expectException('/')
#       self.expectException('/abc')

#       # and we must object to '.' and '..' path segments in the build list
#       self.expectException('.')
#       self.expectException('..')
#       self.expectException('./')
#       self.expectException('..//')
#       self.expectException('./a')
#       self.expectException('../b')
#       self.expectException('a/.')
#       self.expectException('b/..')
#       self.expectException('a/./b')
#       self.expectException('b/../c')

    def doBuildTest(self, title, using_sha):
        check_using_sha(using_sha)
        skPriv = RSA.generate(1024)
        sk = skPriv.publickey()

        if using_sha == Q.USING_SHA1:
            pathToData = os.path.join('example1', 'dataDir')
        elif using_sha == Q.USING_SHA2:
            pathToData = os.path.join('example2', 'dataDir')
        elif using_sha == Q.USING_SHA3:
            pathToData = os.path.join('example3', 'dataDir')
        bl = BuildList.create_from_file_system(
            'a trial list', pathToData, sk, using_sha)

        # check properties ------------------------------------------
        self.assertEqual(bl.title, 'a trial list')
        self.assertEqual(bl.publicKey, sk)
        self.assertEqual(bl.timestamp, timestamp(0))
        self.assertEqual(bl.using_sha, using_sha)

        # check sign() and verify() ---------------------------------

        self.assertEqual(bl, bl)
        self.assertFalse(bl.verify())   # not signed yet

        bl.sign(skPriv)
        sig = bl.digSig                 # this is the base64-encoded value
        self.assertTrue(sig is not None)
        self.assertTrue(bl.verify())    # it has been signed

        # equality, serialization, deserialization ------------------
        self.assertEqual(bl, bl)
        string = bl.toString()
        # DEBUG
        # print("SIGNED BUILD LIST:\n%s" % s)
        # END
        bl2 = BuildList.parse(string, using_sha)
        s2 = bl2.toString()
        self.assertEqual(string, s2)
        self.assertEqual(bl, bl)  # same list, but signed now
        self.assertEqual(bl, bl2)

    def testBuildList(self):
        for using in [Q.USING_SHA1, Q.USING_SHA2, Q.USING_SHA3, ]:
            self.doBuildTest('SHA1 test', using)

    def testNameSpace(self):
        parser = ArgumentParser(description='oh hello')
        args = parser.parse_args()
        args.junk = 'trash'
        self.assertEqual(args.junk, 'trash')


if __name__ == '__main__':
    unittest.main()
