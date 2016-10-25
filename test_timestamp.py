#!/usr/bin/env python3

# buildlist/testTimestamp.py

import hashlib
import os
import time
import unittest

from rnglib import SimpleRNG
from xlattice import u
from buildlist import BuildList


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
        byteCount = BuildList.BLOCK_SIZE * (blkCount - 1) +\
            self.rng.nextInt16(BuildList.BLOCK_SIZE)

        data = bytearray(byteCount)     # that many null bytes
        self.rng.nextBytes(data)             # fill with random data
        dVal = hashlib.new('sha1')
        dVal.update(data)
        hash = dVal.hexdigest()

        file_name = self.rng.nextFileName(8)
        pathToFile = os.path.join('tmp', file_name)
        with open(pathToFile, 'wb') as file:
            file.write(data)

        file_hash = u.file_sha1hex(pathToFile)

        self.assertEqual(hash, file_hash)


if __name__ == '__main__':
    unittest.main()
