#!/usr/bin/python3

# testTimestamp.py

import base64
import hashlib
import os
import time
import unittest

from rnglib import SimpleRNG
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

        print("BLOCK COUNT %d, BYTE COUNT %d\n" % (blkCount, byteCount))

        data = bytearray(byteCount)     # that many null bytes
        self.rng.nextBytes(data)             # fill with random data
        d = hashlib.new('sha1')
        d.update(data)
        hash = d.digest()
        b64Hash = base64.standard_b64encode(hash)

        fileName = self.rng.nextFileName(8)
        pathToFile = os.path.join('tmp', fileName)
        with open(pathToFile, 'wb') as f:
            f.write(data)

        fileB64Hash = base64SHA1File(pathToFile)

        self.assertEqual(b64Hash, fileB64Hash)


if __name__ == '__main__':
    unittest.main()
