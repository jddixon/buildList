# buildList/__init__.py

import base64, calendar, hashlib, time

__all__ = ['__version__', '__version_date__',
            # OTHER EXPORTED CONSTANTS
            'BLOCK_SIZE', 'CONTENT_END', 'CONTENT_START',
            'CRLF',
            # FUNCTIONS
            'base64SHA1File',
            'parseTimestamp', 'timestamp', 'timestampNow', 
          ]

__version__      = '0.1.0'
__version_date__ = '2014-09-30'

BLOCK_SIZE      = 2**18         # 256KB, for no particular reason
CONTENT_END     = '# END CONTENT #'
CONTENT_START   = '# START CONTENT '
CRLF            = "\r\n"


# TIMESTAMP FUNCTIONS -----------------------------------------------

# Note that in the Go code timestamp is an int64, whereas here it
# is a string.

FORMAT = "%Y-%m-%d %H:%M:%S"

def parseTimestamp(s):
    t = time.strptime(s, FORMAT)
    return calendar.timegm(t)

def timestamp(n):       # sec from epoch
    t = time.gmtime(n)
    return time.strftime(FORMAT,  t)

def timestampNow():
    t = time.gmtime()
    return time.strftime(FORMAT,  t)

# SHA1 FILE HASHING -------------------------------------------------

def base64SHA1File(pathToFile):
    """ This does not as yet cope with errors reading the file. """
    with open(pathToFile, 'rb') as f:
        h = hashlib.sha1()
        while True:
            block = f.read(BLOCK_SIZE)
            if not block:
                break
            h.update(block)
    return base64.standard_b64encode(h.digest())
