#!/usr/bin/env python3

# buildList/testTimestamp.py

import hashlib
import os
import time
import unittest

from rnglib import SimpleRNG
from xlattice import u256 as u
from buildList import *


class TestTimestamp (unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    # utility functions #############################################

    # actual unit tests #############################################

    # Note that in the Go code timestamp is an int64, whereas here it
    # is a string.

    def testSHA1File(self):

        blkCount = 1 + self.rng.nextInt16(3)     # so 1 to 3
        # last block will usually be only partically populated
        byteCount = BLOCK_SIZE * (blkCount - 1) + \
            self.rng.nextInt16(BLOCK_SIZE)

        data = bytearray(byteCount)     # that many null bytes
        self.rng.nextBytes(data)             # fill with random data
        d = hashlib.new('sha1')
        d.update(data)
        hash = d.hexdigest()

        fileName = self.rng.nextFileName(8)
        pathToFile = os.path.join('tmp', fileName)
        with open(pathToFile, 'wb') as f:
            f.write(data)

        fileHash = u.fileSHA1Hex(pathToFile)

        self.assertEqual(hash, fileHash)


if __name__ == '__main__':
    unittest.main()
