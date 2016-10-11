#!/usr/bin/env python3

# buildList/testRandomDir.py

import hashlib
import os
import time
import unittest

from buildList import BuildList
from rnglib import SimpleRNG
from xlattice import Q, u, check_using_sha


class TestRandomDir (unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    # utility functions #############################################

    # actual unit tests #############################################

    def doTestRandomDir(self, using_sha):
        check_using_sha(using_sha)
        depth = 1 + self.rng.nextInt16(3)       # so 1 to 3
        width = 1 + self.rng.nextInt16(16)      # so 1 to 16

        blkCount = 1 + self.rng.nextInt16(3)     # so 1 to 3
        # last block will usually be only partically populated
        maxLen = BuildList.BLOCK_SIZE * (blkCount - 1) + \
            self.rng.nextInt16(BuildList.BLOCK_SIZE)
        minLen = 1

        # we want the directory name to be unique
        pathToDir = os.path.join('tmp', self.rng.nextFileName(8))
        while os.path.exists(pathToDir):
            pathToDir = os.path.join('tmp', self.rng.nextFileName(8))

        self.rng.nextDataDir(pathToDir, depth, width, maxLen, minLen)

        data = bytearray(maxLen)            # that many null bytes
        self.rng.nextBytes(data)            # fill with random data
        if using_sha == Q.USING_SHA1:
            d = hashlib.sha1()
        elif using_sha == Q.USING_SHA2:
            d = hashlib.sha256()
        elif using_sha == Q.USING_SHA3:
            d = hashlib.sha3_256()
        d.update(data)
        hash = d.hexdigest()
        fileName = self.rng.nextFileName(8)
        pathToFile = os.path.join('tmp', fileName)
        with open(pathToFile, 'wb') as f:
            f.write(data)
        if using_sha == Q.USING_SHA1:
            fileHash = u.fileSHA1Hex(pathToFile)
        elif using_sha == Q.USING_SHA2:
            fileHash = u.fileSHA2Hex(pathToFile)
        elif using_sha == Q.USING_SHA3:
            fileHash = u.fileSHA3Hex(pathToFile)
        self.assertEqual(hash, fileHash)

    def testRandomDir(self):
        for using in [Q.USING_SHA1, Q.USING_SHA2, Q.USING_SHA3, ]:
            self.doTestRandomDir(using)

if __name__ == '__main__':
    unittest.main()
