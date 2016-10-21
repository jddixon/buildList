#!/usr/bin/env python3
# testPopulateDataDir.py

import base64
import os
import time
import unittest
from Crypto.PublicKey import RSA

from argparse import ArgumentParser

from rnglib import SimpleRNG
from xlattice import Q, check_using_sha
from xlattice.u import UDir
from xlattice.util import timestamp
from buildList import *


class TestPopulateDataDir (unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    # utility functions #############################################

    def make_unique(self, below):
        """ create a unique subdirectory of the directory named """

        dir_path = os.path.join(below, self.rng.nextFileName(8))
        while os.path.exists(dir_path):
            dir_path = os.path.join(below, self.rng.nextFileName(8))
        tmpDir = os.makedirs(dir_path, mode=0o755)

        # DEBUG
        # print("dir_path: %s" % dir_path)
        # END
        return dir_path

    # actual unit tests #############################################

    def do_pop_test(self, using_sha):
        check_using_sha(using_sha)
        # DEBIG
        # print("do_pop_test: %s" % using_sha)
        # EMD

        sk_priv = RSA.generate(1024)
        sk = sk_priv.publickey()

        if using_sha == Q.USING_SHA1:
            originalData = os.path.join('example1', 'dataDir')
            originalU = os.path.join('example1', 'uDir')
        elif using_sha == Q.USING_SHA2:
            originalData = os.path.join('example2', 'dataDir')
            originalU = os.path.join('example2', 'uDir')
        elif using_sha == Q.USING_SHA3:
            originalData = os.path.join('example3', 'dataDir')
            originalU = os.path.join('example3', 'uDir')

        bl = BuildList.create_from_file_system(
            'name_of_the_list', originalData, sk, using_sha)

        # should return an empty list: a basic sanity check
        unmatched = bl.check_in_data_dir(originalData)
        # DEBUG
        #print("UNMATCHED IN DATA DIR: ", unmatched)
        # if len(unmatched) > 0:
        #   print("BL:\n%s" % bl.__str__())
        #   print("in the buildList, but not in uData:")
        #   for un in unmatched:
        #       print("    %s %s" % (un[1], un[0]))
        # END
        self.assertEqual(len(unmatched), 0)

        # should return an empty list: a basic sanity check
        unmatched = bl.check_in_u_dir(originalU)
        # DEBUG
        #print("UNMATCHED IN U DIR: ", unmatched)
        # if len(unmatched) > 0:
        #    print("BL:\n%s" % bl.__str__())
        #    print("in the buildList, but not in u_dir:")
        #    for un in unmatched:
        #        print("    %s %s" % (un[1], un[0]))
        # END
        self.assertEqual(len(unmatched), 0)

        self.assertEqual(bl.title, 'name_of_the_list')
        self.assertEqual(bl.publicKey, sk)
        self.assertEqual(bl.timestamp, timestamp(0))
        self.assertEqual(bl.using_sha, using_sha)

        self.assertEqual(bl, bl)
        self.assertFalse(bl.verify())   # not signed yet

        bl.sign(sk_priv)
        sig = bl.digSig                 # this is the base64-encoded value
        self.assertTrue(sig is not None)
        self.assertTrue(bl.verify())    # it has been signed

        self.assertEqual(bl, bl)

        # BL2: we build testDir and the new dataDir and u_dir --------

        string = bl.toString()
        bl2 = BuildList.parse(string, using_sha)     # round-tripped build list
        s2 = bl2.toString()
        self.assertEqual(string, s2)
        self.assertEqual(bl, bl)                # same list, but signed now
        self.assertEqual(bl, bl2)

        # create empty test directories -------------------
        testPath = self.make_unique('tmp')
        u_path = os.path.join(testPath, 'u_dir')
        u_dir = UDir.discover(
            u_path, using_sha=using_sha)  # creates empty UDir
        dvczPath = os.path.join(testPath, 'dvcz')
        os.mkdir(dvczPath)

        data_path = os.path.join(testPath, bl.tree.name)
        # DEBUG
        # print("DATA_PATH: %s" % data_path)
        # print("DVCZ_DIR:  %s" % dvczPath)
        # print("U_PATH:    %s" % u_path)
        # END

        # populate the new dataDir and then the new u_dir --
        #bl2.populateDataDir(originalU, data_path)
        bl.populateDataDir(originalU, data_path)
        self.assertEqual(len(bl2.check_in_data_dir(data_path)), 0)

        bl2.tree.save_to_u_dir(data_path, u_path, using_sha)
        self.assertEqual(len(bl2.check_in_u_dir(u_path)), 0)

        # BL3:

        # this writes the buildList to dvczPath/lastBuildList:
        bl3 = BuildList.listGen("title", data_path, dvczPath,
                                u_path=u_path, using_sha=using_sha)
        path_to_list = os.path.join(dvczPath, 'lastBuildList')
        with open(path_to_list, 'r') as file:
            s4 = file.read()
        bl4 = BuildList.parse(s4, using_sha)
        s41 = bl4.toString()
        self.assertEqual(s41, s4)

        # DEBUG
        # print('BL  TREE:\n%s' % bl.tree)
        # print('BL2 TREE:\n%s' % bl2.tree)
        # print('BL3 TREE:\n%s' % bl3.tree)
        # print('BL4 TREE:\n%s' % bl4.tree)
        # END

        self.assertEqual(bl4.tree, bl.tree)

    def test_populate_data_dir(self):
        for using in [Q.USING_SHA1, Q.USING_SHA2, ]:
            self.do_pop_test(using)

    def test_name_space(self):
        parser = ArgumentParser(description='oh hello')
        args = parser.parse_args()
        args.junk = 'trash'
        self.assertEqual(args.junk, 'trash')


if __name__ == '__main__':
    unittest.main()
