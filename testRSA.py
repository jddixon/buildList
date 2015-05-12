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
        keyFile = os.path.join(nodeDir, 'skPriv.pem')
        with open(keyFile, 'r') as f:
            skPriv = RSA.importKey(f.read())

        # get the public part of the key
        sk = skPriv.publickey()

        # transform key into DER (binary) format
        skPrivDerFile = os.path.join(nodeDir, 'skPriv.der')
        derData = skPriv.exportKey('DER')
        with open(skPrivDerFile, 'wb') as f:
            f.write(derData)

        # write the public key in PEM format
        skFile = os.path.join(nodeDir, 'sk.pem')
        with open(skFile, 'wb') as f:
            f.write(sk.exportKey('PEM'))

        # write the public key in OpenSSH format
        oFile = os.path.join(nodeDir, 'sk.openssh')
        with open(oFile, 'wb') as f:
            f.write(sk.exportKey('OpenSSH'))

        skPriv2 = RSA.importKey(derData)
        sk2 = skPriv2.publickey()

        # verify that public key parts are identical 
        self.assertEqual( sk.exportKey('DER'), sk2.exportKey('DER'))

        # DEBUG
        pemFormOfCK = sk.exportKey('PEM')
        pemStr      = pemFormOfCK.decode('utf-8')
        print("pubkey in PEM format:\n%s\n" % pemStr)
        # END

        # TEST DIG SIG ----------------------------------------------

        count = 64 + self.rng.nextInt16(192)
        data  = self.rng.someBytes(count)
        self.assertTrue(skPriv.can_sign())
        # self.assertFalse(sk, can_sign())  # no such method

        h = SHA.new()
        h.update(data)
        signer = PKCS1_PSS.new(skPriv)
        signature = signer.sign(h)     # guess at interface ;-)

        b64sig = base64.b64encode(signature).decode('utf-8')
        # DEBUG
        print("DIG SIG:\n%s" % b64sig)
        # END
        sig2 = base64.b64decode(b64sig)
        self.assertEqual(sig2, signature)

        h = SHA.new()
        h.update(data)
        verifier = PKCS1_PSS.new(sk)
        self.assertTrue(verifier.verify(h, signature))

        # twiddle a random byte in data array to make verification fail
        h2 = SHA.new()
        which = self.rng.nextInt16(count)
        data[which] = 0xff & ~data[which]
        h2.update(data)
        self.assertFalse(verifier.verify(h2, signature))

if __name__ == '__main__':
    unittest.main()
