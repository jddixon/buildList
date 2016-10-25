#!/usr/bin/env python3

# test_build_list.py

import os
import sys
import time
import unittest
from Crypto.PublicKey import RSA

from argparse import ArgumentParser

from rnglib import SimpleRNG
from xlattice import QQQ, check_using_sha
from xlattice.util import timestamp
from buildlist import BuildList


class TestBuildList (unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    # utility functions #############################################

    # actual unit tests #############################################

    def expect_exception(self, path_to_dir):
        # DEBUG
        # print("ENTERING expect_exception, path = '%s'" % pathToDir)
        # END
        try:
            BuildList.create_from_file_system('anything', path_to_dir, None)
            self.fail("accepted '%s' as pathToDir")
        except RuntimeError as exc:
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
        sk_ = sk_priv.publickey()

        if using_sha == QQQ.USING_SHA1:
            path_to_data = os.path.join('example1', 'dataDir')
        elif using_sha == QQQ.USING_SHA2:
            path_to_data = os.path.join('example2', 'dataDir')
        elif using_sha == QQQ.USING_SHA3:
            path_to_data = os.path.join('example3', 'dataDir')
        blist = BuildList.create_from_file_system(
            'a trial list', path_to_data, sk_, using_sha)

        # check properties ------------------------------------------
        self.assertEqual(blist.title, 'a trial list')
        self.assertEqual(blist.public_key, sk_)
        self.assertEqual(blist.timestamp, timestamp(0))
        self.assertEqual(blist.using_sha, using_sha)

        # check sign() and verify() ---------------------------------

        self.assertEqual(blist, blist)
        self.assertFalse(blist.verify())   # not signed yet

        blist.sign(sk_priv)
        sig = blist.dig_sig                 # this is the base64-encoded value
        self.assertTrue(sig is not None)
        self.assertTrue(blist.verify())    # it has been signed

        # equality, serialization, deserialization ------------------
        self.assertEqual(blist, blist)
        bl_string = blist.__str__()
        tree_string = blist.tree.__str__()
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
        self.assertEqual(blist, blist)  # same list, but signed now
        # self.assertEqual(bl, bl2)     # XXX timestamps may not be equal

    def test_build_list(self):
        for using in [QQQ.USING_SHA1, QQQ.USING_SHA2, QQQ.USING_SHA3, ]:
            self.do_build_test('SHA1 test', using)

    def test_namespace(self):
        parser = ArgumentParser(description='oh hello')
        args = parser.parse_args()
        args._ = 'trash'
        self.assertEqual(args._, 'trash')


if __name__ == '__main__':
    unittest.main()
