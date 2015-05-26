#!/usr/bin/python3

# testRandomDir.py

import base64, hashlib, os, time, unittest

from rnglib         import SimpleRNG
from buildList      import *

class TestRandomDir (unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG( time.time() )
    def tearDown(self):
        pass

    # utility functions #############################################
    
    # actual unit tests #############################################
    
    def testRandomDir (self):

        depth = 1 + self.rng.nextInt16(3)       # so 1 to 3
        width = 1 + self.rng.nextInt16(16)      # so 1 to 16
        
        blkCount = 1 + self.rng.nextInt16(3)     # so 1 to 3
        # last block will usually be only partically populated
        maxLen = BLOCK_SIZE * (blkCount - 1) + self.rng.nextInt16(BLOCK_SIZE)
        print("MAX FILE BLOCKS %d, MAX FILE LEN %d\n" % (blkCount, maxLen))
        minLen = 1

        # we want the directory name to be unique
        pathToDir = os.path.join('tmp', self.rng.nextFileName(8))
        while os.path.exists(pathToDir):
            pathToDir = os.path.join('tmp', self.rng.nextFileName(8))

        print("SCRATCH DIRECTORY: %s" % pathToDir)
        print("  DEPTH %d, WIDTH %d, MAXLEN %d, MINLEN %d\n" % (
                depth, width, maxLen, minLen))

        self.rng.nextDataDir(pathToDir, depth, width, maxLen, minLen)

        #data = bytearray(maxLen)            # that many null bytes
        #self.rng.nextBytes(data)            # fill with random data
        #d = hashlib.new('sha1')
        #d.update(data)
        #hash = d.digest()
        #b64Hash = base64.standard_b64encode(hash)
        #fileName = self.rng.nextFileName(8)
        #pathToFile = os.path.join('tmp', fileName)
        #with open(pathToFile, 'wb') as f:
        #    f.write(data)
        #fileB64Hash = base64SHA1File(pathToFile)
        #self.assertEqual(b64Hash, fileB64Hash)


if __name__ == '__main__':
    unittest.main()
