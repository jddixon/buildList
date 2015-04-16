# buildList/__init__.py

import base64, calendar, hashlib, time

__all__ = ['__version__', '__version_date__',
            # OTHER EXPORTED CONSTANTS
            'BLOCK_SIZE', 'CONTENT_END', 'CONTENT_START',
            'CRLF', 'LF',
            # FUNCTIONS
            'base64SHA1File',
            'parseTimestamp', 'timestamp', 'timestampNow', 
            # PARSER FUNCTIONS
            'IntegrityCheckFailure', 'ParseFailed',
            'acceptContentLine',
            'acceptListLine', 'expectListLine', 
            'expectStr', 
            'expectTimestamp',
            'expectTitle',
          ]

__version__      = '0.2.3'
__version_date__ = '2015-04-16'

BLOCK_SIZE      = 2**18         # 256KB, for no particular reason
CONTENT_END     = '# END CONTENT #'
CONTENT_START   = '# START CONTENT #'
CRLF            = '\r\n'
LF              = '\n'


# TIMESTAMP FUNCTIONS -----------------------------------------------

# Note that in the Go code timestamp is an int64, whereas here it
# is a string.
# Note also that these functions will misbehave from 2038 or so.

FORMAT = "%Y-%m-%d %H:%M:%S"

def parseTimestamp(s):
    """ May raise ValueError """
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

# PARSER ------------------------------------------------------------
def IntegrityCheckFailure(Exception):
    pass
def ParseFailed(Exception):
    pass

def acceptListLine(f):
    line = f.readline()
    lenLine = len(line)
    if lenLine:
        if line.endswith(CRLF):
            line = line[:lenLine-2]
        elif line.endswith(LF):
            line = line[:lenLine-1]
        else:
            raise ParseFailed("expected CRLF or LF")
    return line

def expectListLine(f, errMsg):
    line = acceptListLine(f)
    if not line:
        raise ParseFailed(errMsg)
    return line

def expectTitle(f, digest):
    line = expectListLine(f, "missing title")
    # DEBUG
    print("TITLE: %s" % line)
    # END
    digest.update(line)

def expectTimestamp(f, digest):
    line = expectListLine(f, "missing timestamp")
    t = parseTimestamp(line)        # can raise ValueError
    # DEBUG
    print("TIMESTAMP: %s" % line)
    # END
    digest.update(line)

def expectStr(f, str):
    """ Raise an exception if the next line doesn't match str. """
    line = expectListLine(f, "expected " + str)
    if line != str:
        raise ParseFailure('expected ' + str)
    # DEBUG
    print("STR: %s" % str)
    # END

def acceptContentLine(f, digest, str, rootDir, uDir):
    """ 
    Accept either a content line or a delimiter (str).  Anything else
    raises an exception.  Returns True if content line matched, False
    if delimiter detected; otherwise raises a ParseFailed.  
    
    NOT IMPLEMENTED: If rootDir is not None, compares the content hash 
    with that of the file at the relative path.  
    
    NOT IMPLEMENTED: If uDir is not None, verifies that the content key
    matches that of a file present in uDir.
    """
    line = acceptListLine(f)        # may raise ParseFailed
    if line == str:
        # DEBUG
        print("STR: " + line)
        # END
        return False
    
    # Parse the content line
    parts = line.split()
    if len(parts) != 2:
        errMsg = "bad content line: '%s'" % line
        raise ParseFailure(errMsg)
    # DEBUG
    print("CONTENT: %s" % line)
    # END
    digest.update(line)
    b64Hash = parts[0]
    path    = parts[1]
    
    # XXX NO CHECK AGAINST rootDir
    # XXX NO CHECK AGAINST uDir

    return True
