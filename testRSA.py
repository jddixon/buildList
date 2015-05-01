#!/usr/bin/python3

# testRSA.py

import base64, hashlib, os, time, unittest
from Crypto.PublicKey import RSA
from Crypto.Hash      import SHA    # presumably 1
from Crypto.Signature import PKCS1_PSS

from rnglib         import SimpleRNG
from buildList      import *

class TestRSA (unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG( time.time() )
    def tearDown(self):
        pass

    def testRSA (self):

        # TEST SERIALIZATIon, DESERIALIZATION OF KEYS ---------------

        # we begin with the private key in PEM (text) format
        nodeDir = os.path.join('example', 'node')
        self.assertTrue(os.path.exists(nodeDir))    
        keyFile = os.path.join(nodeDir, 'ckPriv.pem')
        with open(keyFile, 'r') as f:
            ckPriv = RSA.importKey(f.read())

        # get the public part of the key
        ck = ckPriv.publickey()

        # transform key into DER (binary) format
        ckPrivDerFile = os.path.join(nodeDir, 'ckPriv.der')
        derData = ckPriv.exportKey('DER')
        with open(ckPrivDerFile, 'wb') as f:
            f.write(derData)

        # write the public key in PEM format
        ckFile = os.path.join(nodeDir, 'ck.pem')
        with open(ckFile, 'wb') as f:
            f.write(ck.exportKey('PEM'))

        # write the public key in OpenSSH format
        oFile = os.path.join(nodeDir, 'ck.openssh')
        with open(oFile, 'wb') as f:
            f.write(ck.exportKey('OpenSSH'))

        ckPriv2 = RSA.importKey(derData)
        ck2 = ckPriv2.publickey()

        # verify that public key parts are identical 
        self.assertEqual( ck.exportKey('DER'), ck2.exportKey('DER'))

        # DEBUG
        pemFormOfCK = ck.exportKey('PEM')
        pemStr      = pemFormOfCK.decode('utf-8')
        print("pubkey in PEM format:\n%s\n" % pemStr)
        # END

        # TEST DIG SIG ----------------------------------------------

        count = 64 + self.rng.nextInt16(192)
        data  = self.rng.someBytes(count)
        self.assertTrue(ckPriv.can_sign())
        # self.assertFalse(ck, can_sign())  # no such method

        h = SHA.new()
        h.update(data)
        signer = PKCS1_PSS.new(ckPriv)
        signature = signer.sign(h)     # guess at interface ;-)

        b64sig = base64.b64encode(signature).decode('utf-8')
        # DEBUG
        print("DIG SIG:\n%s" % b64sig)
        # END
        sig2 = base64.b64decode(b64sig)
        self.assertEqual(sig2, signature)

        h = SHA.new()
        h.update(data)
        verifier = PKCS1_PSS.new(ck)
        self.assertTrue(verifier.verify(h, signature))

        # twiddle a random byte in data array to make verification fail
        h2 = SHA.new()
        which = self.rng.nextInt16(count)
        data[which] = 0xff & ~data[which]
        h2.update(data)
        self.assertFalse(verifier.verify(h2, signature))

if __name__ == '__main__':
    unittest.main()
