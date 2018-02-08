#!/usr/bin/env python3
# buildlist/testRandomDir.py

"""
Test building quasi-random data files and directory structures.

XXX This appears to be incomplete.  Why wouldn't this functionality
not be in rnglib?
"""
import os
import sys
import time
import unittest
import hashlib

from buildlist import BuildList
from rnglib import SimpleRNG
from xlattice import HashTypes, u, check_hashtype

if sys.version_info < (3, 6):
    # pylint:disable=unused-import
    import sha3         # monkey-patches hashlib
    assert sha3         # suppress warning


class TestRandomDir(unittest.TestCase):
    """ Test building quasi-random data files and directory structures. """

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    # utility functions #############################################

    # actual unit tests #############################################

    def do_test_random_dir(self, hashtype):
        """ Test building random directories with specific SHA hash type. """
        check_hashtype(hashtype)
        depth = 1 + self.rng.next_int16(3)       # so 1 to 3
        width = 1 + self.rng.next_int16(16)      # so 1 to 16

        blk_count = 1 + self.rng.next_int16(3)     # so 1 to 3
        # last block will usually be only partically populated
        max_len = BuildList.BLOCK_SIZE * (blk_count - 1) +\
            self.rng.next_int16(BuildList.BLOCK_SIZE)
        min_len = 1

        # we want the directory name to be unique
        path_to_dir = os.path.join('tmp', self.rng.next_file_name(8))
        while os.path.exists(path_to_dir):
            path_to_dir = os.path.join('tmp', self.rng.next_file_name(8))

        self.rng.next_data_dir(path_to_dir, depth, width, max_len, min_len)

        data = bytearray(max_len)            # that many null bytes
        self.rng.next_bytes(data)            # fill with random data
        if hashtype == HashTypes.SHA1:
            sha = hashlib.sha1()
        elif hashtype == HashTypes.SHA2:
            sha = hashlib.sha256()
        elif hashtype == HashTypes.SHA3:
            # pylint:disable=no-member
            sha = hashlib.sha3_256()
        elif hashtype == HashTypes.BLAKE2B:
            sha = hashlib.blake2b(digest_size=32)
        else:
            raise NotImplementedError
        sha.update(data)
        hash_ = sha.hexdigest()
        file_name = self.rng.next_file_name(8)
        path_to_file = os.path.join('tmp', file_name)
        with open(path_to_file, 'wb') as file:
            file.write(data)

        if hashtype == HashTypes.SHA1:
            file_hash = u.file_sha1hex(path_to_file)
        elif hashtype == HashTypes.SHA2:
            file_hash = u.file_sha2hex(path_to_file)
        elif hashtype == HashTypes.SHA3:
            file_hash = u.file_sha3hex(path_to_file)
        elif hashtype == HashTypes.BLAKE2B:
            file_hash = u.file_blake2b_hex(path_to_file)
        else:
            raise NotImplementedError
        self.assertEqual(hash_, file_hash)

    def test_random_dir(self):
        """ Test building random directories with supported SHA hash types. """
        for hashtype in HashTypes:
            self.do_test_random_dir(hashtype)


if __name__ == '__main__':
    unittest.main()
