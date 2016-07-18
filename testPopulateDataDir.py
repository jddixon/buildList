#!/usr/bin/env python3

# testPopulateDataDir.py

import base64
import os
import time
import unittest
from Crypto.PublicKey import RSA

from argparse import ArgumentParser

from rnglib import SimpleRNG
from xlattice.u import UDir
from xlattice.util import timestamp
from buildList import *


class TestPopulateDataDir (unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    # utility functions #############################################

    def makeUnique(self, below):
        """ create a unique subdirectory of the directory named """

        dirPath = os.path.join(below, self.rng.nextFileName(8))
        while os.path.exists(dirPath):
            dirPath = os.path.join(below, self.rng.nextFileName(8))
        tmpDir = os.makedirs(dirPath, mode=0o755)

        # DEBUG
        print("dirPath: %s" % dirPath)
        # END
        return dirPath

    # actual unit tests #############################################

    def doPopTest(self, title, usingSHA1):
        skPriv = RSA.generate(1024)
        sk = skPriv.publickey()

        if usingSHA1:
            originalData = os.path.join('example1', 'dataDir')
            originalU = os.path.join('example1', 'uDir')
        else:
            originalData = os.path.join('example2', 'dataDir')
            originalU = os.path.join('example2', 'uDir')

        bl = BuildList.createFromFileSystem(
            'name_of_the_list', originalData, sk, usingSHA1)

        # should return an empty list: a basic sanity check
        unmatched = bl.checkInDataDir(originalData)
        # DEBUG
        if len(unmatched) > 0:
            print("BL:\n%s" % bl.__str__())
            print("in the buildList, but not in uData:")
            for un in unmatched:
                print("    %s %s" % (un[1], un[0]))
        # END
        self.assertEqual(len(unmatched), 0)

        # should return an empty list: a basic sanity check
        unmatched = bl.checkInUDir(originalU)
        # DEBUG
        if len(unmatched) > 0:
            print("BL:\n%s" % bl.__str__())
            print("in the buildList, but not in uDir:")
            for un in unmatched:
                print("    %s %s" % (un[1], un[0]))
        # END
        self.assertEqual(len(unmatched), 0)

        self.assertEqual(bl.title, 'name_of_the_list')
        self.assertEqual(bl.publicKey, sk)
        self.assertEqual(bl.timestamp, timestamp(0))
        self.assertEqual(bl.usingSHA1, usingSHA1)

        self.assertEqual(bl, bl)
        self.assertFalse(bl.verify())   # not signed yet

        bl.sign(skPriv)
        sig = bl.digSig                 # this is the base64-encoded value
        self.assertTrue(sig is not None)
        self.assertTrue(bl.verify())    # it has been signed

        self.assertEqual(bl, bl)

        # BL2: we build testDir and the new dataDir and uDir --------

        s = bl.toString()
        bl2 = BuildList.parse(s, usingSHA1)     # round-tripped build list
        s2 = bl2.toString()
        self.assertEqual(s, s2)
        self.assertEqual(bl, bl)                # same list, but signed now
        self.assertEqual(bl, bl2)

        # create empty test directories -------------------
        testPath = self.makeUnique('tmp')
        uPath = os.path.join(testPath, 'uDir')
        uDir = UDir.discover(uPath, usingSHA1=usingSHA1)  # creates empty UDir
        dvczPath = os.path.join(testPath, 'dvcz')
        os.mkdir(dvczPath)

        dataPath = os.path.join(testPath, bl.tree.name)
        # DEBUG
        print("DATA_PATH: %s" % dataPath)
        print("DVCZ_DIR:  %s" % dvczPath)
        print("U_PATH:    %s" % uPath)
        # END

        # populate the new dataDir and then the new uDir --
        #bl2.populateDataDir(originalU, dataPath)
        bl.populateDataDir(originalU, dataPath)
        self.assertEqual(len(bl2.checkInDataDir(dataPath)), 0)

        bl2.tree.saveToUDir(dataPath, uPath, usingSHA1)
        self.assertEqual(len(bl2.checkInUDir(uPath)), 0)

        # BL3:

        # this writes the buildList to dvczPath/lastBuildList:
        bl3 = BuildList.listGen("title", dataPath, dvczPath,
                                uPath=uPath, usingSHA1=usingSHA1)
        pathToList = os.path.join(dvczPath, 'lastBuildList')
        with open(pathToList, 'r') as f:
            s4 = f.read()
        bl4 = BuildList.parse(s4, usingSHA1)
        s41 = bl4.toString()
        self.assertEqual(s41, s4)

        # DEBUG
        print('BL  TREE:\n%s' % bl.tree)
        print('BL2 TREE:\n%s' % bl2.tree)
        print('BL3 TREE:\n%s' % bl3.tree)
        print('BL4 TREE:\n%s' % bl4.tree)
        # END

        self.assertEqual(bl4.tree, bl.tree)

    def testPopulateDataDir(self):
        self.doPopTest('SHA1 test', True)
        self.doPopTest('SHA2 test', False)

    def testNameSpace(self):
        parser = ArgumentParser(description='oh hello')
        args = parser.parse_args()
        args.junk = 'trash'
        self.assertEqual(args.junk, 'trash')


if __name__ == '__main__':
    unittest.main()