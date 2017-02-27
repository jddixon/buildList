#!/usr/bin/env python3
# buildlist/testTimestamp.py

""" Ostensibly tests BuildList timestamp.  (Why?) """

import hashlib
import os
import time
import unittest

from rnglib import SimpleRNG
from xlattice import u
from buildlist import BuildList


class TestTimestamp(unittest.TestCase):
    """ Ostensibly tests BuildList timestamp.  (Why?) """

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    def test_sha1_file(self):
        """
        Verify functioning of xlattice.u.file_sha1hex().
        """

        blk_count = 1 + self.rng.next_int16(3)     # so 1 to 3
        # last block will usually be only partically populated
        byte_count = BuildList.BLOCK_SIZE * (blk_count - 1) +\
            self.rng.next_int16(BuildList.BLOCK_SIZE)

        data = bytearray(byte_count)        # that many null bytes
        self.rng.next_bytes(data)           # fill with random data
        d_val = hashlib.new('sha1')
        d_val.update(data)
        hash_ = d_val.hexdigest()

        file_name = self.rng.next_file_name(8)
        path_to_file = os.path.join('tmp', file_name)
        with open(path_to_file, 'wb') as file:
            file.write(data)

        file_hash = u.file_sha1hex(path_to_file)

        self.assertEqual(hash_, file_hash)


if __name__ == '__main__':
    unittest.main()
