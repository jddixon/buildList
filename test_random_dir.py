#!/usr/bin/env python3
# buildlist/testRandomDir.py

import hashlib
import os
import time
import unittest

from buildlist import BuildList
from rnglib import SimpleRNG
from xlattice import QQQ, u, check_using_sha


class TestRandomDir(unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    # utility functions #############################################

    # actual unit tests #############################################

    def do_test_random_dir(self, using_sha):
        check_using_sha(using_sha)
        depth = 1 + self.rng.nextInt16(3)       # so 1 to 3
        width = 1 + self.rng.nextInt16(16)      # so 1 to 16

        blk_count = 1 + self.rng.nextInt16(3)     # so 1 to 3
        # last block will usually be only partically populated
        max_len = BuildList.BLOCK_SIZE * (blk_count - 1) +\
            self.rng.nextInt16(BuildList.BLOCK_SIZE)
        min_len = 1

        # we want the directory name to be unique
        path_to_dir = os.path.join('tmp', self.rng.nextFileName(8))
        while os.path.exists(path_to_dir):
            path_to_dir = os.path.join('tmp', self.rng.nextFileName(8))

        self.rng.nextDataDir(path_to_dir, depth, width, max_len, min_len)

        data = bytearray(max_len)            # that many null bytes
        self.rng.nextBytes(data)            # fill with random data
        # pylint:disable=redefined-variable-type
        if using_sha == QQQ.USING_SHA1:
            sha = hashlib.sha1()
        elif using_sha == QQQ.USING_SHA2:
            sha = hashlib.sha256()
        elif using_sha == QQQ.USING_SHA3:
            sha = hashlib.sha3_256()
        sha.update(data)
        hash_ = sha.hexdigest()
        file_name = self.rng.nextFileName(8)
        path_to_file = os.path.join('tmp', file_name)
        with open(path_to_file, 'wb') as file:
            file.write(data)

        if using_sha == QQQ.USING_SHA1:
            file_hash = u.file_sha1hex(path_to_file)
        elif using_sha == QQQ.USING_SHA2:
            file_hash = u.file_sha2hex(path_to_file)
        elif using_sha == QQQ.USING_SHA3:
            file_hash = u.file_sha3hex(path_to_file)
        self.assertEqual(hash_, file_hash)

    def test_random_dir(self):
        for using in [QQQ.USING_SHA1, QQQ.USING_SHA2, QQQ.USING_SHA3, ]:
            self.do_test_random_dir(using)

if __name__ == '__main__':
    unittest.main()
