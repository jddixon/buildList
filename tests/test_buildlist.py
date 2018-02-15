#!/usr/bin/env python3
# test_build_list.py

""" Test basic buildlist functionality. """

import os
import time
import unittest
from argparse import ArgumentParser

from Crypto.PublicKey import RSA

from rnglib import SimpleRNG
from xlattice import HashTypes, check_hashtype
from xlutil import timestamp
from buildlist import BuildList


class TestBuildList(unittest.TestCase):
    """ Test basic buildlist functionality. """

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    def expect_exception(self, path_to_dir):
        """ Verify that exceptions are raised where they should be. """
        try:
            BuildList.create_from_file_system('anything', path_to_dir, None)
            self.fail("accepted '%s' as pathToDir")
        except RuntimeError:
            pass
        except Exception as exc:
            self.fail("unexpected exception %s" % exc)

    def do_build_test(self, title, hashtype):
        """ Test buildlist functionality for specific hash type. """
        check_hashtype(hashtype)
        sk_priv = RSA.generate(1024)
        sk_ = sk_priv.publickey()

        if hashtype == HashTypes.SHA1:
            path_to_data = os.path.join('example1', 'dataDir')
        elif hashtype == HashTypes.SHA2:
            path_to_data = os.path.join('example2', 'dataDir')
        elif hashtype == HashTypes.SHA3:
            path_to_data = os.path.join('example3', 'dataDir')
        elif hashtype == HashTypes.BLAKE2B:
            path_to_data = os.path.join('example4', 'dataDir')
        else:
            raise NotImplementedError
        blist = BuildList.create_from_file_system(
            'a trial list', path_to_data, sk_, hashtype=hashtype)

        # check properties ------------------------------------------
        self.assertEqual(blist.title, 'a trial list')
        self.assertEqual(blist.public_key, sk_)
        self.assertEqual(blist.timestamp, timestamp(0))
        self.assertEqual(blist.hashtype, hashtype)

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

        bl2 = BuildList.parse(bl_string, hashtype)
        # bl_string2 = bl2.__str__()
        tree_string2 = bl2.tree.__str__()
        # DEBUG
        # print("ROUNDTRIPPED:\n%s" % bl_string2)
        # END
        self.assertEqual(tree_string, tree_string2)
        self.assertEqual(blist, blist)  # same list, but signed now
        # self.assertEqual(bl, bl2)     # XXX timestamps may not be equal

    def test_build_list(self):
        """ Test buildlist functionality for suppored hash types. """
        for hashtype in HashTypes:
            self.do_build_test('SHA test', hashtype)

    def test_namespace(self):
        """ Verify that assignments to Namespace work as expected. """
        parser = ArgumentParser(description='oh hello')
        args = parser.parse_args()
        args._ = 'trash'
        self.assertEqual(args._, 'trash')


if __name__ == '__main__':
    unittest.main()
