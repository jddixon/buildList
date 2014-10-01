#!/usr/bin/python

# testTimestamp.py

import calendar, time, unittest

from rnglib         import SimpleRNG
from buildList      import *

class TestTimestamp (unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG( time.time() )
    def tearDown(self):
        pass

    # utility functions #############################################
    
    # actual unit tests #############################################
    
    # Note that in the Go code timestamp is an int64, whereas here it
    # is a string.

    def testConstructor(self):
        structNow   = time.gmtime()                 # struct_time
        gmtNow      = calendar.timegm(structNow)    # seconds from epoch
        strNow      = timestamp(gmtNow)
        nowAgain    = parseTimestamp(strNow)
        strAgain    = timestamp(nowAgain)
        self.assertEquals(strNow, strAgain)

    def testParser(self):
        DOC_TIME    = "2004-11-18 20:03:34"
        fromEpoch   = parseTimestamp(DOC_TIME)      # seconds from epoch
        fromAsStr   = timestamp(fromEpoch)
        self.assertEquals(fromAsStr, DOC_TIME)

    def testNow(self):
        structNow   = time.gmtime()                 # struct_time
        gmtNow      = calendar.timegm(structNow)    # seconds from epoch
        nowAsStr    = timestampNow()                # in string format
        now2        = parseTimestamp(nowAsStr)
        self.assertTrue( now2 - gmtNow <= 1 )

if __name__ == '__main__':
    unittest.main()
