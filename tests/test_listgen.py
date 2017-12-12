#!/usr/bin/env python3
# test_listgen.py

""" Test BuildList.listgen functionality. """

import os
import time
import unittest
# from argparse import ArgumentParser

# from Crypto.PublicKey import RSA

from rnglib import SimpleRNG
from xlattice import HashTypes
from xlattice.u import DirStruc  # , UDirf    # NOT YET USED
# from xlattice.util import timestamp
from buildlist import BuildList

# We expect this script to be run in $DEV_BASE/py/buildlist
PATH_TO_DATA = os.path.join(
    '..', '..', 'dat', 'xl_testData', 'treeData', 'binExample_1')
DATA_DIR = os.path.join(PATH_TO_DATA, 'dataDir')
RSA_FILE = os.path.join(PATH_TO_DATA, 'node', 'skPriv.pem')


class TestBuildList(unittest.TestCase):
    """ Test BuildList.listgen functionality. """

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    def do_listgen_test(self, title, hashtype, dirstruc):
        """
        Test buildlist functionality for specific hash type and DirStruc.
        """

        # create the BuildList from what's in DATA_DIR
        # -- RESTRUCTURE and just do this once for each hashtype -- in
        #    other words, this should be in a higher level function, one
        #    which runs a test for each dirstruc
        # blist = BuildList.list_gen(   # NOT YET USED
        BuildList.list_gen(
            title=title,
            data_dir=DATA_DIR,
            # dvcz_dir=         # .dvcz
            # list_file=        # lastBuildList
            logging=True,
            u_path=os.path.join('tmp', str(hashtype.value), dirstruc.name),
            hashtype=hashtype,
            using_indir=True
        )

        # THE SAME BUILDLIST IS USED FOR EACH OF THE THREE DIRSTRUCS
        # UNFINISHED

        # Compare the BuildList with
        # UNFINISHED

    def test_build_list(self):
        """ Test listgen functionality for suppored hash types. """

        # DEBUG
        print("DATA_DIR is '%s'" % DATA_DIR)
        # END
        self.assertTrue(os.path.exists(DATA_DIR))
        self.assertTrue(os.path.exists(RSA_FILE))

        for hashtype in HashTypes:
            for dirstruc in DirStruc:
                self.do_listgen_test('SHA test', hashtype, dirstruc)


if __name__ == '__main__':
    unittest.main()
