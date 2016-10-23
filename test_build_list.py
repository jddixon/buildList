#!/usr/bin/env python3

# test_build_list.py

import os
import sys
import time
import unittest
from Crypto.PublicKey import RSA

from argparse import ArgumentParser

from rnglib import SimpleRNG
from xlattice import Q, check_using_sha
from xlattice.util import timestamp
from buildlist import *


class Test_build_list (unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    # utility functions #############################################

    # actual unit tests #############################################

    def expect_exception(self, pathToDir):
        # DEBUG
        # print("ENTERING expect_exception, path = '%s'" % pathToDir)
        # END
        try:
            BuildList.create_from_file_system('anything', pathToDir, None)
            self.fail("accepted '%s' as pathToDir")
        except RuntimeError as e:
            pass
        except Exception as e2:
            self.fail("unexpected exception %s" % e2)

#   def do_test_bad_parts(self):
#       # we object to absolute paths
#       self.expect_exception('/')
#       self.expect_exception('/abc')

#       # and we must object to '.' and '..' path segments in the build list
#       self.expect_exception('.')
#       self.expect_exception('..')
#       self.expect_exception('./')
#       self.expect_exception('..//')
#       self.expect_exception('./a')
#       self.expect_exception('../b')
#       self.expect_exception('a/.')
#       self.expect_exception('b/..')
#       self.expect_exception('a/./b')
#       self.expect_exception('b/../c')

    def do_build_test(self, title, using_sha):
        check_using_sha(using_sha)
        sk_priv = RSA.generate(1024)
        sk = sk_priv.publickey()

        if using_sha == Q.USING_SHA1:
            path_to_data = os.path.join('example1', 'dataDir')
        elif using_sha == Q.USING_SHA2:
            path_to_data = os.path.join('example2', 'dataDir')
        elif using_sha == Q.USING_SHA3:
            path_to_data = os.path.join('example3', 'dataDir')
        bl = BuildList.create_from_file_system(
            'a trial list', path_to_data, sk, using_sha)

        # check properties ------------------------------------------
        self.assertEqual(bl.title, 'a trial list')
        self.assertEqual(bl.public_key, sk)
        self.assertEqual(bl.timestamp, timestamp(0))
        self.assertEqual(bl.using_sha, using_sha)

        # check sign() and verify() ---------------------------------

        self.assertEqual(bl, bl)
        self.assertFalse(bl.verify())   # not signed yet

        bl.sign(sk_priv)
        sig = bl.dig_sig                 # this is the base64-encoded value
        self.assertTrue(sig is not None)
        self.assertTrue(bl.verify())    # it has been signed

        # equality, serialization, deserialization ------------------
        self.assertEqual(bl, bl)
        bl_string = bl.__str__()
        tree_string = bl.tree.__str__()
        # DEBUG
        # print("SIGNED BUILD LIST:\n%s" % bl_string)
        # END

        bl2 = BuildList.parse(bl_string, using_sha)
        bl_string2 = bl2.__str__()
        tree_string2 = bl2.tree.__str__()
        # DEBUG
        # print("ROUNDTRIPPED:\n%s" % bl_string2)
        # END
        self.assertEqual(tree_string, tree_string2)
        self.assertEqual(bl, bl)  # same list, but signed now
        # self.assertEqual(bl, bl2)     # XXX timestamps may not be equal

    def test_build_list(self):
        for using in [Q.USING_SHA1, Q.USING_SHA2, Q.USING_SHA3, ]:
            self.do_build_test('SHA1 test', using)

    def test_namespace(self):
        parser = ArgumentParser(description='oh hello')
        args = parser.parse_args()
        args.junk = 'trash'
        self.assertEqual(args.junk, 'trash')


if __name__ == '__main__':
    unittest.main()
