# buildList/__init__.py

import base64, binascii, calendar, hashlib, os, time
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

__version__      = '0.3.0'
__version_date__ = '2015-05-06'

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
    def __init__(self, title, ck, tree):
        
        self._title     = title
        if (not ck) or (type(ck) != RSA._RSAobj) :
            raise "ck is nil or not a valid RSA public key"
        self._publicKey = ck
   
        if (not tree) or (type(tree) != MerkleTree):
            raise 'tree is nil or not a valid MerkleTree'

        self._tree      = tree

        self._usingSHA1 = tree.usingSHA1    # REDUNDANT 

        self._when      = 0         # seconds from the Epoch; a 64-bit value
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
    def publicKey(self):    return self._publicKey

    @property
    def timestamp(self):    return timestamp(self._when)

    @property
    def title(self):        return self._title

    @property
    def tree(self):         return self._tree

    @property
    def usingSHA1(self):    return self._usingSHA1

    def _getBuildListSHA1(self):

        h = SHA.new()

        # add public key and then CRLF to hash
        pemCK = self._publicKey.exportKey('PEM')
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
        # XXX truncating loses microseconds
        now = int(time.time())      # seconds from Epoch
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

    # EQUALITY ------------------------------------------------------
    def equal(self, other):
        if (not other) or (type(other) != BuildList):
            return False
        if self.title != other.title:
            return False
        if self.publicKey != other.publicKey :
            return False
        if not self.tree.equal(other.tree):
            return False
        if self._when != other._when:
            print("  my when = %f, other when = %f" % (self._when, other._when))
            return False

        if self._digSig == None:
            return other._digSig == None
        else:
            return self.digSig == other.digSig

    # SERIALIZATION -------------------------------------------------
    @staticmethod
    def createFromFileSystem(title, pathToDir, ck, 
            usingSHA1=False, exRE=None, matchRE=None):
        
        #############################################################
        # XXX pathToDir must be a relative path containing no . or ..
        #############################################################
        
        if (not pathToDir) or (not os.path.isdir(pathToDir)):
            raise "%s does not exist or is not a directory" % pathToDir

        tree = MerkleTree.createFromFileSystem(pathToDir,
            # accept default deltaIndent
            usingSHA1=usingSHA1, exRE=exRE)

        return BuildList(title, ck, tree)

    @staticmethod
    def parse(s):
        """ 
        This relies upon the fact that all fields are separated by 
        CRLF sequences.
        """
        if s == None:
            raise RuntimeError('BuildList.parse: empty input')
        if type(s) is not str:
            s = str(s, 'utf-8')
        ss = s.split('\r\n')
        return BuildList.parseFromStrings(ss)

    @staticmethod
    def _expectField(ss, n):
        """ 
        Complain if the Nth field does not exist.  Return the index
        of the next field.
        """
        if n >= len(ss):
            raise "Missing %d-th field in BuildList"
        field = ss[n]
        n += 1
        return field, n

    @staticmethod
    def parseFromStrings(ss):
        if ss == None:
            raise "parseFromStrings: null argument"

        # expect a PEM-encoded publid key with embedded newlines
        n = 0
        serCK, n = BuildList._expectField(ss, n)
        myCK = RSA.importKey(serCK)

        # expect a title
        myTitle, n = BuildList._expectField(ss, n)

        # expect a timestamp
        myTimestamp, n = BuildList._expectField(ss, n)

        # expect CONTENT-START
        startLine, n = BuildList._expectField(ss, n)
        if startLine != CONTENT_START:
            raise "expected CONTENT_START line"

        # expect a serialized MerkleTree followed by a CONTENT END
        mtLines = []
        while True:
            line, n = BuildList._expectField(ss, n)
            if line == CONTENT_END:
                break
            else:
                mtLines.append(line)
        # expect default indents
        myTree = MerkleTree.createFromStringArray(mtLines) 

        # expect an empty line
        space, n = BuildList._expectField(ss, n)
        if space != '':
            raise "expected an empty line"

        # accept a digital signature if it is present
        if n < len(ss):
            myDigSig = ss[n]

        bld = BuildList(myTitle, myCK, myTree)
        bld._when   = parseTimestamp(myTimestamp)
        bld._digSig = binascii.a2b_base64(myDigSig)
        return bld

    def __str__(self):
        return self.toString()

    def toString(self):
        """ 
        In this serialization, each field appears followed by a CR-LF
        sequence.
        """
        ss = self.toStrings()
        return '\r\n'.join(ss)
    
    def toStrings(self):
        ss = []

        # public key (with embedded newlines)
        pemCK = self.publicKey.exportKey('PEM').decode('utf-8')
        ss.append(pemCK)

        # title 
        ss.append(self.title )

        # timestamp 
        ss.append(self.timestamp)

        # content start line
        ss.append(CONTENT_START)

        # merkle tree
        ssTree = self.tree.toString().split('\r\n')
        if (len(ssTree) > 1) and (ssTree[-1] == ''):
            ssTree = ssTree[0:-1]
        ss += ssTree

        # content end line
        ss.append(CONTENT_END)

        # empty line
        ss.append('')

        # dig sig
        ss.append(self.digSig)

        return ss

