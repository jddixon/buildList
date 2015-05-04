#!/usr/bin/python3

# testBuildList.py

import base64, hashlib, os, time, unittest
from Crypto.PublicKey import RSA

from rnglib         import SimpleRNG
from buildList      import *

class TestBuildList (unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG( time.time() )
    def tearDown(self):
        pass

    # utility functions #############################################
    
    # actual unit tests #############################################
   
    def doBuildTest(self, title, usingSHA1):

        ckPriv = RSA.generate(1024)
        ck     = ckPriv.publickey()

        pathToData = os.path.join('example', 'dataDir')
        bl = BuildList('a trial list', pathToData, ck, usingSHA1)

        # check properties ------------------------------------------
        self.assertEqual(bl.title,      'a trial list')
        self.assertEqual(bl.path,       pathToData)
        self.assertEqual(bl.publicKey,  ck)
        self.assertEqual(bl.timestamp,  timestamp(0))
        self.assertEqual(bl.usingSHA1, usingSHA1)

        # check sign() and verify() ---------------------------------

        self.assertFalse(bl.verify())   # not signed yet
        bl.sign(ckPriv)
        sig = bl.digSig                 # this is the base64-encoded value
        self.assertTrue(sig != None)
        self.assertTrue(bl.verify())    # it has been signed

    def testBuildList (self):

        self.doBuildTest('SHA1 test', True)
        self.doBuildTest('SHA2 test', False)

if __name__ == '__main__':
    unittest.main()
