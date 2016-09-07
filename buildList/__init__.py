# buildList/__init__.py

import base64
import binascii
import calendar
import hashlib
import os
import time

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA, SHA256
from Crypto.Signature import PKCS1_PSS

from nlhtree import NLHNode, NLHTree, NLHLeaf

from xlattice.crypto import collectPEMRSAPublicKey
from xlattice.lfs import touch
from xlattice.u import Q, UDir
from xlattice.util import makeExRE, parseTimestamp, timestamp, timestampNow

__all__ = ['__version__', '__version_date__',
           # FUNCTIONS
           'checkDirsInPath',
           "generateRSAKey",
           "readRSAKey", 'rm_f_dirContents',
           # PARSER FUNCTIONS
           'acceptContentLine',
           'acceptListLine', 'expectListLine',
           'expectStr',
           'expectTimestamp',
           'expectTitle',
           # CLASSES
           'BuildList',
           'BLIntegrityCheckFailure', 'BLParseFailed', 'BLError',
           ]

__version__ = '0.7.1'
__version_date__ = '2016-09-07'

# UTILITY FUNCTIONS -------------------------------------------------


def checkDirsInPath(pathToFile):
    # if a path to the file is specified, create intervening directories
    # if they don't exist
    if pathToFile:
        dir, delim, fileName = pathToFile.rpartition('/')
        if dir:
            os.makedirs(dir, 0o711, exist_ok=True)

# this should be in some common place ...


def rm_f_dirContents(dir):
    if not dir:
        print('directory must be named')
        sys.exit(1)
    if dir[0] == '/' or (dir.find('..') != -1):
        print("illegal path for rm_f_dirContents(): '%s'" % dir)
        sys.exit(1)
    for file in os.listdir(dir):
        pathToFile = os.path.join(dir, file)
        if os.path.isfile(pathToFile):
            os.unlink(pathToFile)
        elif os.path.isdir(pathToFile):
            shutil.rmtree(pathToFile)
    # allow exceptions to bubble up

# RSA KEY PAIR ------------------------------------------------------


def generateRSAKey(pathToFile, bitCount=2048):
    """
    Generate an RSA key and write it to disk in PEM format.  The key size
    should be no less than 1024 bits.
    """

    checkDirsInPath(pathToFile)

    key = RSA.generate(bitCount)
    with open(pathToFile, 'wb+') as f:
        f.write(key.exportKey('PEM'))
    os.chmod(pathToFile, 0o600)


def readRSAKey(pathToFile):
    with open(pathToFile, 'rb') as f:
        key = RSA.importKey(f.read())
    return key

# PARSER ------------------------------------------------------------


class BLIntegrityCheckFailure(BaseException):
    pass


class BLParseFailed(BaseException):
    pass


def acceptListLine(f):
    line = f.readline()
    lenLine = len(line)
    if lenLine:
        if line.endswith(LF):
            line = line[:lenLine - 2]
        elif line.endswith(LF):
            line = line[:lenLine - 1]
        else:
            raise BLParseFailed("expected LF")
    return line


def expectListLine(f, errMsg):
    line = acceptListLine(f)
    if not line:
        raise BLParseFailed(errMsg)
    return line


def expectTitle(f, digest):
    line = expectListLine(f, "missing title")
    # DEBUG
    # print("TITLE: %s" % line)
    # END
    digest.update(line)


def expectTimestamp(f, digest):
    line = expectListLine(f, "missing timestamp")
    t = parseTimestamp(line)        # can raise ValueError
    # DEBUG
    #print("TIMESTAMP: %s" % line)
    # END
    digest.update(line)


def expectStr(f, str):
    """ Raise an exception if the next line doesn't match str. """
    line = expectListLine(f, "expected " + str)
    if line != str:
        raise ParseFailure('expected ' + str)
    # DEBUG
    # print("STR: %s" % str)
    # END


def acceptContentLine(f, digest, str, rootPath, uPath):
    """
    Accept either a content line or a delimiter (str).  Anything else
    raises an exception.  Returns True if content line matched, False
    if delimiter detected; otherwise raises a BLParseFailed.

    NOT IMPLEMENTED: If rootPath is not None, compares the content hash
    with that of the file at the relative path.

    NOT IMPLEMENTED: If uPath is not None, verifies that the content key
    matches that of a file present in uPath.
    """
    line = acceptListLine(f)        # may raise BLParseFailed
    if line == str:
        # DEBUG
        # print("STR: " + line)
        # END
        return False

    # Parse the content line
    parts = line.split()
    if len(parts) != 2:
        errMsg = "bad content line: '%s'" % line
        raise ParseFailure(errMsg)
    # DEBUG
    # print("CONTENT: %s" % line)
    # END
    digest.update(line)
    b64Hash = parts[0]
    path = parts[1]

    # XXX NO CHECK AGAINST rootPath
    # XXX NO CHECK AGAINST uPath

    return True

# -- CLASSES --------------------------------------------------------


class BLError(RuntimeError):
    pass


class BuildList(object):
    """
    A BuildList has a title, an RSA public key, and some content, which
    is an NLHTree, an indented list of directories and files and their
    associated content hashes.  The BuildList optionally has a timestamp
    and a digital signature.  It is signed using the RSA private key
    associated with the RSA public key.  Signing the BuildList updates
    the timestamp.  The BuildList has a verify() method which
    mathematically verifies that the digital signature is compatible
    with the title, timestamp, content lines, and the BuildList's RSA
    public key.
    """

    # constants
    BLOCK_SIZE = 2**18         # 256KB, for no particular reason
    CONTENT_END = '# END CONTENT #'
    CONTENT_START = '# BEGIN CONTENT #'
    LF = '\n'.encode('utf-8')

    # XXX DROP by v1.0.0
    OLD_CONTENT_START = '# START CONTENT #'
    # XXX END DROP

    def __init__(self, title, sk, tree):

        self._title = title.strip()
        if (not sk) or (not isinstance(sk, RSA._RSAobj)):
            raise BLError("sk is nil or not a valid RSA public key")
        self._publicKey = sk

        if (not tree) or (not isinstance(tree, NLHTree)):
            raise BLError('tree is nil or not a valid NLHTree')

        self._tree = tree

        self._usingSHA = tree.usingSHA    # REDUNDANT

        self._when = 0         # seconds from the Epoch; a 64-bit value
        self._digSig = None

    @property
    def digSig(self):
        """
        Take care: we store the binary value but this returns it
        base64-encoded.
        """
        return base64.b64encode(self._digSig).decode('utf-8')

    @property
    def exRE(self): return self._exRE

    @property
    def publicKey(self): return self._publicKey

    @property
    def signed(self): return self._digSig is not None

    @property
    def timestamp(self): return timestamp(self._when)

    @property
    def title(self): return self._title

    @property
    def tree(self): return self._tree

    @property
    def usingSHA(self): return self._usingSHA

    def _getBuildListSHA1(self):
        h = SHA.new()
        # add public key and then LF to hash
        pemCK = self._publicKey.exportKey('PEM')
        h.update(pemCK)
        h.update(BuildList.LF)

        # add title and LF to hash
        h.update(self._title.encode('utf-8'))
        h.update(BuildList.LF)

        # add timestamp and LF to hash
        h.update(self.timestamp.encode('utf-8'))
        h.update(BuildList.LF)

        # add CONTENT_START and LF line to hash
        h.update((BuildList.CONTENT_START + '\n').encode('utf-8'))

        # add serialized NLHTree to hash, each line terminated by LF
        h.update(self._tree.__str__().encode('utf-8'))

        # add CONTENT_END and LF line to hash
        h.update((BuildList.CONTENT_END + '\n').encode('utf-8'))

        # add LF to hash
        h.update(BuildList.LF)
        return h

    def sign(self, skPriv):
        """ skPriv is the RSA private key used for siging the BuildList """

        if self._digSig is not None:
            raise BLError("buildList has already been signed")

        # Verify that the public key (sk) is the public part of skPriv,
        # the private RSA key.
        if (not skPriv) or (not isinstance(skPriv, RSA._RSAobj)):
            raise BLError("skPriv is nil or not a valid RSA key")
        if skPriv.publickey() != self._publicKey:
            raise BLError("skPriv does not match BuildList's public key")

        # the time is part of what is signed, so we need to set it now
        # XXX truncating loses microseconds
        now = int(time.time())      # seconds from Epoch
        self._when = now

        h = self._getBuildListSHA1()

        # Sign the list using SHA1 and RSA.  What we are signing is the
        # in-memory binary data structure.
        signer = PKCS1_PSS.new(skPriv)
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
    def __eq__(self, other):
        if (not other) or (not isinstance(other, BuildList)):
            # DEBUG
            # if not other:
            #    print("other is None")
            # else:
            #    print("other is %s" % type(other))
            # END
            return False
        if self.title != other.title:
            # DEBUG
            # print("my title is '%s' but other's is '%s'" % (
            #    self.title, other.title))
            # END
            return False
        if self.publicKey != other.publicKey:
            return False
        if not (self.tree == other.tree):
            # DEBUG
            # print("NLHTrees differ")
            # END
            return False
        if self._when != other._when:
            print(
                "  my when = %f, other when = %f" %
                (self._when, other._when))
            return False

        if self._digSig is None:
            return other._digSig is None
        else:
            return self.digSig == other.digSig

    # SERIALIZATION -------------------------------------------------
    @staticmethod
    def createFromFileSystem(title, pathToDir, sk,
                             usingSHA=Q.USING_SHA2, exRE=None, matchRE=None):

        if (not pathToDir) or (not os.path.isdir(pathToDir)):
            raise BLError(
                "%s does not exist or is not a directory" % pathToDir)

        tree = NLHTree.createFromFileSystem(pathToDir,
                                            # accept default deltaIndent
                                            usingSHA=usingSHA, exRE=exRE)
        return BuildList(title, sk, tree)

    @staticmethod
    def parse(s, usingSHA):
        """
        This relies upon the fact that all fields are separated by
        LF ('\n').
        """
        if s is None:
            raise BLParseFailed('BuildList.parse: empty input')
        if not isinstance(s, str):
            s = str(s, 'utf-8')
        ss = s.split('\n')
        return BuildList.parseFromStrings(ss, usingSHA)

    @staticmethod
    def _expectField(ss, n):
        """
        Complain if the Nth field does not exist.  Return the index
        of the next field.
        """
        if n >= len(ss):
            raise BLParseFailed("Missing %d-th field in BuildList")
        field = ss[n]
        n += 1
        return field, n

    @staticmethod
    def parseFromStrings(ss, usingSHA):
        # DEBUG
        # print("parseFromStrings: usingSHA = %s" % usingSHA)
        # END
        if ss is None:
            raise BLParseFailed("parseFromStrings: null argument")

        # expect a PEM-encoded public key with embedded newlines
        firstLine = ss[0]
        ss = ss[1:]
        serCK, ss = collectPEMRSAPublicKey(firstLine, ss)
        myCK = RSA.importKey(serCK)

        n = 0

        # expect a title
        myTitle, n = BuildList._expectField(ss, n)

        # expect a timestamp
        myTimestamp, n = BuildList._expectField(ss, n)

        # expect CONTENT-START
        startLine, n = BuildList._expectField(ss, n)
        if (startLine != BuildList.CONTENT_START) and \
                (startLine != BuildList.OLD_CONTENT_START):
            # DEBUG
            # print("Expected CONTENT START, got '%s'" % startLine)
            # END
            raise BLParseFailed("expected BEGIN CONTENT line")

        # expect a serialized NLHTree followed by a CONTENT END
        mtLines = []
        while True:
            line, n = BuildList._expectField(ss, n)
            if line == BuildList.CONTENT_END:
                break
            else:
                mtLines.append(line)
        # expect default indents
        myTree = NLHTree.createFromStringArray(mtLines, usingSHA)

        # expect an empty line
        space, n = BuildList._expectField(ss, n)
        if space != '':
            raise BLParseFailed("expected an empty line")

        # accept a digital signature if it is present
        if n < len(ss):
            myDigSig = ss[n]

        bld = BuildList(myTitle, myCK, myTree)
        bld._when = parseTimestamp(myTimestamp)
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
        return '\n'.join(ss)

    def toStrings(self):
        ss = []

        # public key (with embedded newlines)
        pemCK = self.publicKey.exportKey('PEM').decode('utf-8')
        ss.append(pemCK)

        # title
        ss.append(self.title)

        # timestamp
        ss.append(self.timestamp)

        # content start line
        ss.append(BuildList.CONTENT_START)

        # NLHTree
        ssTree = self.tree.__str__().split('\n')
        if (len(ssTree) > 1) and (ssTree[-1] == ''):
            ssTree = ssTree[0:-1]
        ss += ssTree

        # content end line
        ss.append(BuildList.CONTENT_END)

        # empty line
        ss.append('')

        # dig sig
        if self._digSig:
            ss.append(self.digSig)

        return ss

    # OTHER CONSTRUCTORS --------------------------------------------

    @classmethod
    def listGen(cls, title, dataDir,
                dvczDir='.dvcz',
                listFile='lastBuildList',
                keyFile=os.path.join(
                        os.environ['DVCZ_PATH_TO_KEYS'], 'skPriv.pem'),
                excl=['build'],
                logging=False,
                uPath='',
                usingSHA=Q.USING_SHA2):
        """
        Create a BuildList for dataDir with the title indicated.
        Files matching the globs in excl will be skipped.  'build'
        should always be in the list.  If a private key is specified
        and signing is True, the BuildList will be digitally signed.
        If uPath is specified, the files in dataDir will be posted to uDir.
        If usingSHA is True, an SHA1 hash will be used for the digital
        signature.  Otherwise SHA2 will be used

        If there is a title, we try to read the version number from
        the first line of .dvcz/version.  If that exists, we append
        a space and then the version number to the title.
        """
        version = '0.0.0'
        pathToVersion = os.path.join(dvczDir, 'version')
        if os.path.exists(pathToVersion):
            with open(pathToVersion, 'r') as f:
                version = f.readline().strip()
                title = title + ' v' + version
                # DEBUG
                # print("title with version is '%s'" % title)
                # END

        exRE = makeExRE(excl)
        signing = keyFile != ''
        if signing:
            with open(keyFile, 'r') as f:
                skPriv = RSA.importKey(f.read())
            sk = skPriv.publickey()
        else:
            sk = None
        bl = cls.createFromFileSystem(title, dataDir, sk,
                                      usingSHA, exRE, matchRE=None)
        if signing:
            bl.sign(skPriv)

        newData = bl.__str__().encode('utf-8')
        if usingSHA == Q.USING_SHA1:
            sha = hashlib.sha1()
        else:
            # FIX ME FIX ME FIX ME
            sha = hashlib.sha256()
        sha.update(newData)
        newHash = sha.hexdigest()
        pathToListing = os.path.join(dvczDir, listFile)

        if uPath:

            bl.tree.saveToUDir(dataDir, uPath, usingSHA)

            # insert this BuildList into U
            # DEBUG
            # print("writing BuildList with hash %s into %s" % (newHash, uPath))
            # END
            uDir = UDir.discover(uPath)
            # DEBUG
            # print("listGen:")
            #print("  uDir:      %s" % uPath)
            #print("  dirStruc:  %s" % UDir.dirStrucToName(uDir.dirStruc))
            #print("  usingSHA: %s" % uDir.usingSHA)
            # END
            (length, hashBack) = uDir.putData(newData, newHash)
            if hashBack != newHash:
                print("WARNING: wrote %s to %s, but actual hash is %s" % (
                    newHash, uPath, hashBack))

        # CHANGES TO DATADIR AFTER UPDATING uPath ===================

        # serialize the BuildList, typically to .dvcz/lastBuildList
        with open(pathToListing, 'wb+') as f:
            f.write(newData)

        # DEBUG
        # print("hash of buildList at %s is %s" % (pathToListing, newHash))
        # END
        if logging:
            pathToLog = os.path.join(dvczDir, 'builds')
            with open(pathToLog, 'a') as f:
                f.write("%s v%s %s\n" % (bl.timestamp, version, newHash))

        return bl

    def populateDataDir(self, uPath, dataPath):
        # uPath path to U, including directory name
        # dataPath, path to dataDir, including directory name (which
        #   must be the same as the name of the tree)

        if not os.path.exists(uPath):
            raise RuntimeError("uPath %s does not exist" % uPath)

        relPath, junk, name = dataPath.rpartition('/')
        if name != self.tree.name:
            raise RuntimeError(
                "name mismatch: tree name %s but dataDir name %s" % (
                    self.tree.name, name))

        os.makedirs(relPath, exist_ok=True, mode=0o755)
        self.tree.populateDataDir(uPath, relPath)

    # OTHER METHODS =================================================

    def checkInDataDir(self, dataPath):
        """
        Whether the BuildList's component files are present in the
        data directory named.  Returns a list of content hashes for
        files not found.
        """
        return self.tree.checkInDataDir(dataPath)

    def checkInUDir(self, uPath):
        """
        Whether the BuildList's component files are present in the
        U directory named.  Returns a list of content hashes for
        files not found.
        """
        return self.tree.checkInUDir(uPath)
