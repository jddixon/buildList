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
        skPriv = RSA.generate(1024)
        sk     = skPriv.publickey()

        pathToData = os.path.join('example', 'dataDir')
        bl = BuildList.createFromFileSystem(
                'a trial list', pathToData, sk, usingSHA1)

        # check properties ------------------------------------------
        self.assertEqual(bl.title,      'a trial list')
        self.assertEqual(bl.publicKey,  sk)
        self.assertEqual(bl.timestamp,  timestamp(0))
        self.assertEqual(bl.usingSHA1, usingSHA1)

        # check sign() and verify() ---------------------------------

        self.assertTrue(bl.equal(bl))
        self.assertFalse(bl.verify())   # not signed yet

        bl.sign(skPriv)
        sig = bl.digSig                 # this is the base64-encoded value
        self.assertTrue(sig != None)
        self.assertTrue(bl.verify())    # it has been signed

        # equality, serialization, deserialization ------------------
        self.assertTrue(bl.equal(bl))
        s = bl.toString()
        bl2 = BuildList.parse(s)
        s2  = bl2.toString()
        self.assertEqual(s, s2)
        self.assertTrue( bl.equal(bl))  # same list, but signed now
        self.assertTrue( bl.equal(bl2)) 

    def testBuildList (self):

        self.doBuildTest('SHA1 test', True)
        self.doBuildTest('SHA2 test', False)

if __name__ == '__main__':
    unittest.main()
