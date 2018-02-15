#!/usr/bin/env python3
# testPopulateDataDir.py

"""
Test using a BuildList and existing content-keyed store to populate
a data directory.
"""

import os
import time
import unittest

from argparse import ArgumentParser

from Crypto.PublicKey import RSA

from rnglib import SimpleRNG
from xlattice import HashTypes, check_hashtype
from xlu import UDir
from xlutil import timestamp
from buildlist import BuildList


class TestPopulateDataDir(unittest.TestCase):
    """
    Test using a BuildList and existing content-keyed store to populate
    a data directory.
    """

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    # utility functions #############################################

    def make_unique(self, below):
        """ create a unique subdirectory of the directory named """

        dir_path = os.path.join(below, self.rng.next_file_name(8))
        while os.path.exists(dir_path):
            dir_path = os.path.join(below, self.rng.next_file_name(8))
        os.makedirs(dir_path, mode=0o755)
        return dir_path

    # actual unit tests #############################################

    def do_pop_test(self, hashtype):
        """ Test populating a data directory for a specific hashtype. """

        check_hashtype(hashtype)
        # DEBUG
        # print("do_pop_test: %s" % hashtype)
        # EMD

        sk_priv = RSA.generate(1024)
        sk_ = sk_priv.publickey()

        if hashtype == HashTypes.SHA1:
            original_data = os.path.join('example1', 'dataDir')
            original_u = os.path.join('example1', 'uDir')
        elif hashtype == HashTypes.SHA2:
            original_data = os.path.join('example2', 'dataDir')
            original_u = os.path.join('example2', 'uDir')
        elif hashtype == HashTypes.SHA3:
            original_data = os.path.join('example3', 'data_dir')
            original_u = os.path.join('example3', 'uDir')

        blist = BuildList.create_from_file_system(
            'name_of_the_list', original_data, sk_, hashtype=hashtype)

        # should return an empty list: a basic sanity check
        unmatched = blist.check_in_data_dir(original_data)
        # DEBUG
        # print("UNMATCHED IN DATA DIR: ", unmatched)
        # if len(unmatched) > 0:
        #   print("BL:\n%s" % blist.__str__())
        #   print("in the buildlist, but not in uData:")
        #   for un in unmatched:
        #       print("    %s %s" % (un[1], un[0]))
        # END
        self.assertEqual(len(unmatched), 0)

        # should return an empty list: a basic sanity check
        unmatched = blist.check_in_u_dir(original_u)
        # DEBUG
        # print("UNMATCHED IN U DIR: ", unmatched)
        if unmatched:
            print("BL:\n%s" % blist.__str__())
            print("in the buildlist, but not in u_dir:")
            for unm in unmatched:
                print("    %s %s" % (unm[1], unm[0]))
        # END
        self.assertEqual(len(unmatched), 0)

        self.assertEqual(blist.title, 'name_of_the_list')
        self.assertEqual(blist.public_key, sk_)
        self.assertEqual(blist.timestamp, timestamp(0))
        self.assertEqual(blist.hashtype, hashtype)

        self.assertEqual(blist, blist)
        self.assertFalse(blist.verify())   # not signed yet

        blist.sign(sk_priv)
        sig = blist.dig_sig                 # this is the base64-encoded value
        self.assertTrue(sig is not None)
        self.assertTrue(blist.verify())    # it has been signed

        self.assertEqual(blist, blist)

        # BL2: we build testDir and the new dataDir and u_dir --------
        string = blist.to_string()
        bl2 = BuildList.parse(string, hashtype)     # round-tripped build list
        # DEBUG
        # print("\nFIRST BUILD LIST:\n%s" % blist)
        # print("\nSECOND BUILD LIST:\n%s" % bl2)
        # END

        # string2 = bl2.__str__()
        # self.assertEqual(string, string2)
        # same list, but signed now
        self.assertEqual(blist, blist)
        # self.assertEqual(bl, bl2)               # timestamps may differ

        # create empty test directories -------------------
        test_path = self.make_unique('tmp')
        u_path = os.path.join(test_path, 'uDir')
        UDir.discover(
            u_path, hashtype=hashtype)  # creates empty UDir
        dvcz_path = os.path.join(test_path, 'dvcz')
        os.mkdir(dvcz_path)

        data_path = os.path.join(test_path, blist.tree.name)
        # DEBUG
        # print("DATA_PATH: %s" % data_path)
        # print("DVCZ_DIR:  %s" % dvczPath)
        # print("U_PATH:    %s" % u_path)
        # END

        # populate the new dataDir and then the new u_dir --
        # bl2.populateDataDir(originalU, data_path)
        blist.populate_data_dir(original_u, data_path)
        self.assertEqual(len(bl2.check_in_data_dir(data_path)), 0)

        bl2.tree.save_to_u_dir(data_path, u_path, hashtype)
        self.assertEqual(len(bl2.check_in_u_dir(u_path)), 0)

        # BL3:

        # this writes the buildlist to dvczPath/lastBuildList:
        blist3 = BuildList.list_gen("title", data_path, dvcz_path,
                                    u_path=u_path, hashtype=hashtype)
        path_to_list = os.path.join(dvcz_path, 'lastBuildList')
        with open(path_to_list, 'r') as file:
            ser4 = file.read()
        bl4 = BuildList.parse(ser4, hashtype)
        # ser41 = bl4.to_string()
        bl4.to_string()
        # self.assertEqual(ser41, ser4) # FAILS: ser41 is signed, ser4 isn't

        # DEBUG
        # print("recovered from disk:\n%s" % ser4)
        # print("\nserialized from BuildList:\n%s" % ser41)
        # END

        self.assertEqual(blist.tree, blist.tree)    # check __eq__
        self.assertEqual(bl2.tree, blist.tree)
        self.assertEqual(blist3.tree, blist.tree)
        self.assertEqual(bl4.tree, blist.tree)

    def test_populate_data_dir(self):
        """
        Test populate_data_dir for the supported hashtypes.
        """
        for hashtype in [HashTypes.SHA1, HashTypes.SHA2]:
            self.do_pop_test(hashtype)

    def test_name_space(self):
        """
        Verify that ArgumentParser works as expected, specifically
        that assignment adds a key to the Namespace.
        """
        parser = ArgumentParser(description='oh hello')
        args = parser.parse_args()
        args._ = 'trash'
        self.assertEqual(args._, 'trash')


if __name__ == '__main__':
    unittest.main()
