#!/usr/bin/env python3

# buildList/testRandomDir.py

import hashlib
import os
import time
import unittest
from xlattice import u

from rnglib import SimpleRNG
from buildList import *


class TestRandomDir (unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    # utility functions #############################################

    # actual unit tests #############################################

    def doTestRandomDir(self, usingSHA1):

        depth = 1 + self.rng.nextInt16(3)       # so 1 to 3
        width = 1 + self.rng.nextInt16(16)      # so 1 to 16

        blkCount = 1 + self.rng.nextInt16(3)     # so 1 to 3
        # last block will usually be only partically populated
        maxLen = BLOCK_SIZE * (blkCount - 1) + self.rng.nextInt16(BLOCK_SIZE)
        minLen = 1

        # we want the directory name to be unique
        pathToDir = os.path.join('tmp', self.rng.nextFileName(8))
        while os.path.exists(pathToDir):
            pathToDir = os.path.join('tmp', self.rng.nextFileName(8))

        self.rng.nextDataDir(pathToDir, depth, width, maxLen, minLen)

        data = bytearray(maxLen)            # that many null bytes
        self.rng.nextBytes(data)            # fill with random data
        if usingSHA1:
            d = hashlib.new('sha1')
        else:
            d = hashlib.new('sha256')
        d.update(data)
        hash = d.hexdigest()
        fileName = self.rng.nextFileName(8)
        pathToFile = os.path.join('tmp', fileName)
        with open(pathToFile, 'wb') as f:
            f.write(data)
        if usingSHA1:
            fileHash = u.fileSHA1Hex(pathToFile)
        else:
            fileHash = u.fileSHA2Hex(pathToFile)
        self.assertEqual(hash, fileHash)

    def testRandomDir(self):
        self.doTestRandomDir(True)
        self.doTestRandomDir(False)

if __name__ == '__main__':
    unittest.main()
