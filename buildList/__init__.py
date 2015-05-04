# buildList/__init__.py

import base64, calendar, hashlib, os, time
from Crypto.PublicKey import RSA
from Crypto.Hash      import SHA, SHA256
from Crypto.Signature import PKCS1_PSS
from merkletree import MerkleTree

__all__ = ['__version__', '__version_date__',
            # OTHER EXPORTED CONSTANTS
            'BLOCK_SIZE', 'CONTENT_END', 'CONTENT_START',
            'CRLF', 'LF',
            # FUNCTIONS
            'base64SHA1File',
            'parseTimestamp', 'timestamp', 'timestampNow', 'touch',
            # PARSER FUNCTIONS
            'IntegrityCheckFailure', 'ParseFailed',
            'acceptContentLine',
            'acceptListLine', 'expectListLine',
            'expectStr',
            'expectTimestamp',
            'expectTitle',
            # CLASSES
            'BuildList',
          ]

__version__      = '0.2.9'
__version_date__ = '2015-05-04'

BLOCK_SIZE      = 2**18         # 256KB, for no particular reason
CONTENT_END     = '# END CONTENT #'
CONTENT_START   = '# START CONTENT #'
CRLF            = '\r\n'.encode('utf-8')
LF              = '\n'

def touch(fname, times=None):
    with open(fname, 'a'):
        os.utime(fname, times)

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

class BuildList(object):
    """
    A BuildList has a title, an RSA public key, and some content, which
    is a MerkleTree, an indented list of files and directories and their
    associated content hashes.  The BuildList optionally has a timestamp
    and a digital signature.  It is signed using the RSA private key
    associated with the RSA public key.  Signing the BuildList updates
    the timestamp.  The BuildList has a verify() method which
    mathematically verifies that the digital signature is compatible
    with the title, timestamp, content lines, and the BuildList's RSA
    public key.
    """
    def __init__(self, title, path, ck, usingSHA1=False, exRE=None):
        self._publicKey = ck
        if (not ck) or (type(ck) != RSA._RSAobj) :
            raise "ck is nil or not a valid RSA public key"
        self._title     = title
        self._when      = 0         # seconds from the Epoch; a 64-bit value
        self._path      = path   # a relative path containing no . or ..
        if (not path) or (not os.path.isdir(path)):
            raise "%s does not exist or is not a directory" % path
        self._usingSHA1 = usingSHA1

        self._tree = MerkleTree.createFromFileSystem(path,
            # accept default deltaIndent
            usingSHA1=usingSHA1, exRE=exRE)
        self._digSig = None

    @property
    def digSig(self):
        """ 
        Take care: we store the binary value but this returns it
        base64-encoded.
        """
        return base64.b64encode(self._digSig).decode('utf-8')

    @property
    def exRE(self):         return self._exRE

    @property
    def path(self):         return self._path

    @property
    def publicKey(self):    return self._publicKey

    @property
    def timestamp(self):    return timestamp(self._when)

    @property
    def title(self):        return self._title

    @property
    def usingSHA1(self):    return self._usingSHA1

    def _getBuildListSHA1(self):

        h = SHA.new()

        # add public key and then CRLF to hash
        pemCK = self._publicKey.exportKey('PEM') # .decode('utf-8')
        h.update(pemCK)
        h.update(CRLF)

        # add title and CRLF to hash
        h.update(self._title.encode('utf-8'))
        h.update(CRLF)

        # add timestamp and CRLF to hash
        h.update(self.timestamp.encode('utf-8'))
        h.update(CRLF)

        # add CONTENT_START and CRLF line to hash
        h.update((CONTENT_START + '\r\n').encode('utf-8'))

        # add serialized MerkleTree to hash, each line terminated by CRLF
        h.update( self._tree.toString('').encode('utf-8'))

        # add CONTENT_END and CRLF line to hash
        h.update((CONTENT_END + '\r\n').encode('utf-8'))

        # add CRLF to hash
        h.update(CRLF)
        return h


    def sign(self, ckPriv):
        """ ckPriv is the RSA private key used for siging the BuildList """

        if self._digSig != None:
            raise "buildList has already been signed"

        # Verify that the public key (ck) is the public part of ckPriv,
        # the private RSA key.
        if (not ckPriv) or (type(ckPriv) != RSA._RSAobj) :
            raise "ckPriv is nil or not a valid RSA key"
        if ckPriv.publickey() != self._publicKey:
            raise "ckPriv does not match BuildList's public key"

        # the time is part of what is signed, so we need to set it now
        now = time.time()       # seconds from Epoch
        self._when = now

        h = self._getBuildListSHA1()

        # Sign the list using SHA1 and RSA.  What we are signing is the
        # in-memory binary data structure.
        signer = PKCS1_PSS.new(ckPriv)
        self._digSig = signer.sign(h)

    def verify(self):

        # if self._signature is not set, return False
        success = False

        if self._digSig:

	        # otherwise, return True if self._signature is set and it is
	        # consistent as an RSA-SHA1 with the public key on the
	        # document and the SHA1 hash of the serialized document, taking
	        # the hash over the fields in standard order (pubkey, title,
	        # timestamp, and content lines).

            h = self._getBuildListSHA1()
            verifier = PKCS1_PSS.new(self.publicKey)
            success = verifier.verify(h, self._digSig)

        return success

    # SERIALIZATION -------------------------------------------------
    @staticmethod
    def createFromFileSystem(pathToDir, usingSHA1=False, 
            exRE=None, matchRE=None):
        
        pass

    @staticmethod
    def createFromSerialization(s):
        if s == None:
            raise RuntimeError('BuildList.createFromSerialization: empty input')
        if type(s) is not str:
            s = str(s, 'utf-8')
        ss = s.split('\r\n')
        return BuildList.createFromStringArray(ss)

    @staticmethod
    def createFromStringArray(ss):
        if ss == None:
            raise "createFromStringArray: null argument"
        pass

    def __str__(self):
        return self.toString()

    def toString(self):
        pass

