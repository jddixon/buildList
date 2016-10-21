# buildList/__init__.py

import base64
import binascii
import calendar
import os
import time

import hashlib
import sha3         # XXX should be conditional

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA, SHA256
from Crypto.Signature import PKCS1_PSS

from nlhtree import NLHNode, NLHTree, NLHLeaf

from xlattice.crypto import collect_pem_rsa_public_key
from xlattice.lfs import touch
from xlattice.u import Q, UDir, check_using_sha
from xlattice.util import make_ex_re, parse_timestamp, timestamp, timestamp_now

__all__ = ['__version__', '__version_date__',
           # FUNCTIONS
           'check_dirs_in_path',
           "generate_rsa_key",
           "read_rsa_key", 'rm_f_dir_contents',
           # PARSER FUNCTIONS
           'accept_content_line',
           'accept_list_line', 'expect_list_line',
           'expect_str',
           'expect_timestamp',
           'expect_title',
           # CLASSES
           'BuildList',
           'BLIntegrityCheckFailure', 'BLParseFailed', 'BLError',
           ]

__version__ = '0.8.0'
__version_date__ = '2016-10-21'

# UTILITY FUNCTIONS -------------------------------------------------


def check_dirs_in_path(pathToFile):
    # if a path to the file is specified, create intervening directories
    # if they don't exist
    if pathToFile:
        dir, delim, fileName = pathToFile.rpartition('/')
        if dir:
            os.makedirs(dir, 0o711, exist_ok=True)

# this should be in some common place ...


def rm_f_dir_contents(dir):
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


def generate_rsa_key(pathToFile, bitCount=2048):
    """
    Generate an RSA key and write it to disk in PEM format.  The key size
    should be no less than 1024 bits.
    """

    check_dirs_in_path(pathToFile)

    key = RSA.generate(bitCount)
    with open(pathToFile, 'wb+') as file:
        file.write(key.exportKey('PEM'))
    os.chmod(pathToFile, 0o600)


def read_rsa_key(pathToFile):
    with open(pathToFile, 'rb') as file:
        key = RSA.importKey(file.read())
    return key

# PARSER ------------------------------------------------------------


class BLIntegrityCheckFailure(BaseException):
    pass


class BLParseFailed(BaseException):
    pass


def accept_list_line(file):
    line = file.readline()
    lenLine = len(line)
    if lenLine:
        if line.endswith(LF):
            line = line[:lenLine - 2]
        elif line.endswith(LF):
            line = line[:lenLine - 1]
        else:
            raise BLParseFailed("expected LF")
    return line


def expect_list_line(file, errMsg):
    line = accept_list_line(file)
    if not line:
        raise BLParseFailed(errMsg)
    return line


def expect_title(file, digest):
    line = expect_list_line(file, "missing title")
    # DEBUG
    # print("TITLE: %s" % line)
    # END
    digest.update(line)


def expect_timestamp(file, digest):
    line = expect_list_line(file, "missing timestamp")
    tstamp = parse_timestamp(line)        # can raise ValueError
    # DEBUG
    #print("TIMESTAMP: %s" % line)
    # END
    digest.update(line)


def expect_str(file, str):
    """ Raise an exception if the next line doesn't match str. """
    line = expect_list_line(file, "expected " + str)
    if line != str:
        raise ParseFailure('expected ' + str)
    # DEBUG
    # print("STR: %s" % str)
    # END


def accept_content_line(file, digest, str, rootPath, u_path):
    """
    Accept either a content line or a delimiter (str).  Anything else
    raises an exception.  Returns True if content line matched, False
    if delimiter detected; otherwise raises a BLParseFailed.

    NOT IMPLEMENTED: If rootPath is not None, compares the content hash
    with that of the file at the relative path.

    NOT IMPLEMENTED: If u_path is not None, verifies that the content key
    matches that of a file present in u_path.
    """
    line = accept_list_line(file)        # may raise BLParseFailed
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
    # XXX NO CHECK AGAINST u_path

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
    def using_sha(self): return self._tree._using_sha

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
    def create_from_file_system(title, pathToDir, sk,
                                using_sha=Q.USING_SHA2, exRE=None, matchRE=None):

        if (not pathToDir) or (not os.path.isdir(pathToDir)):
            raise BLError(
                "%s does not exist or is not a directory" % pathToDir)

        tree = NLHTree.create_from_file_system(pathToDir,
                                               # accept default deltaIndent
                                               using_sha=using_sha, ex_re=exRE)
        return BuildList(title, sk, tree)

    @staticmethod
    def parse(string, using_sha):
        """
        This relies upon the fact that all fields are separated by
        LF ('\n').
        """

        if string is None:
            raise BLParseFailed('BuildList.parse: empty input')
        if not isinstance(string, str):
            string = str(string, 'utf-8')
        strings = string.split('\n')
        return BuildList.parseFromStrings(strings, using_sha)

    @staticmethod
    def _expectField(strings, n):
        """
        Complain if the Nth field does not exist.  Return the index
        of the next field.
        """
        if n >= len(strings):
            raise BLParseFailed("Missing %d-th field in BuildList")
        field = strings[n]
        n += 1
        return field, n

    @staticmethod
    def parseFromStrings(strings, using_sha):

        check_using_sha(using_sha)

        # DEBUG
        # print("parseFromStrings: using_sha = %s" % using_sha)
        # END
        if strings is None:
            raise BLParseFailed("parseFromStrings: null argument")

        # expect a PEM-encoded public key with embedded newlines
        firstLine = strings[0]
        strings = strings[1:]
        serCK, strings = collect_pem_rsa_public_key(firstLine, strings)
        myCK = RSA.importKey(serCK)

        n = 0

        # expect a title
        myTitle, n = BuildList._expectField(strings, n)

        # expect a timestamp
        myTimestamp, n = BuildList._expectField(strings, n)

        # expect CONTENT-START
        startLine, n = BuildList._expectField(strings, n)
        if (startLine != BuildList.CONTENT_START) and\
                (startLine != BuildList.OLD_CONTENT_START):
            # DEBUG
            # print("Expected CONTENT START, got '%s'" % startLine)
            # END
            raise BLParseFailed("expected BEGIN CONTENT line")

        # expect a serialized NLHTree followed by a CONTENT END
        mtLines = []
        while True:
            line, n = BuildList._expectField(strings, n)
            if line == BuildList.CONTENT_END:
                break
            else:
                mtLines.append(line)
        # expect default indents
        myTree = NLHTree.create_from_string_array(mtLines, using_sha)

        # expect an empty line
        space, n = BuildList._expectField(strings, n)
        if space != '':
            raise BLParseFailed("expected an empty line")

        # accept a digital signature if it is present
        if n < len(strings):
            myDigSig = strings[n]

        bld = BuildList(myTitle, myCK, myTree)
        bld._when = parse_timestamp(myTimestamp)
        bld._digSig = binascii.a2b_base64(myDigSig)
        return bld

    def __str__(self):
        return self.toString()

    def toString(self):
        """
        In this serialization, each field appears followed by a CR-LF
        sequence.
        """
        strings = self.to_strings()
        return '\n'.join(strings)

    def to_strings(self):
        strings = []

        # public key (with embedded newlines)
        pemCK = self.publicKey.exportKey('PEM').decode('utf-8')
        strings.append(pemCK)

        # title
        strings.append(self.title)

        # timestamp
        strings.append(self.timestamp)

        # content start line
        strings.append(BuildList.CONTENT_START)

        # NLHTree
        ssTree = self.tree.__str__().split('\n')
        if (len(ssTree) > 1) and (ssTree[-1] == ''):
            ssTree = ssTree[0:-1]
        strings += ssTree

        # content end line
        strings.append(BuildList.CONTENT_END)

        # empty line
        strings.append('')

        # dig sig
        if self._digSig:
            strings.append(self.digSig)

        return strings

    # OTHER CONSTRUCTORS --------------------------------------------

    @classmethod
    def listGen(cls, title, dataDir,
                dvczDir='.dvcz',
                listFile='lastBuildList',
                keyFile=os.path.join(
                        os.environ['DVCZ_PATH_TO_KEYS'], 'skPriv.pem'),
                excl=['build'],
                logging=False,
                u_path='',
                using_sha=Q.USING_SHA1):     # NOTE default is SHA1
        """
        Create a BuildList for dataDir with the title indicated.
        Files matching the globs in excl will be skipped.  'build'
        should always be in the list.  If a private key is specified
        and signing is True, the BuildList will be digitally signed.
        If u_path is specified, the files in dataDir will be posted to uDir.
        By default SHA1 hash will be used for the digital
        signature.

        If there is a title, we try to read the version number from
        the first line of .dvcz/version.  If that exists, we append
        a space and then the version number to the title.
        """
        version = '0.0.0'
        pathToVersion = os.path.join(dvczDir, 'version')
        if os.path.exists(pathToVersion):
            with open(pathToVersion, 'r') as file:
                version = file.readline().strip()
                title = title + ' v' + version
                # DEBUG
                # print("title with version is '%s'" % title)
                # END

        exRE = make_ex_re(excl)
        signing = keyFile != ''
        if signing:
            with open(keyFile, 'r') as file:
                skPriv = RSA.importKey(file.read())
            sk = skPriv.publickey()
        else:
            sk = None
        bl = cls.create_from_file_system(title, dataDir, sk,
                                         using_sha, exRE, matchRE=None)
        if signing:
            bl.sign(skPriv)

        newData = bl.__str__().encode('utf-8')
        if using_sha == Q.USING_SHA1:
            sha = hashlib.sha1()
        elif using_sha == Q.USING_SHA2:
            sha = hashlib.sha256()
        elif using_sha == Q.USING_SHA3:
            sha = hashlib.sha3_256()
        sha.update(newData)
        newHash = sha.hexdigest()
        pathToListing = os.path.join(dvczDir, listFile)

        if u_path:

            bl.tree.save_to_u_dir(dataDir, u_path, using_sha)

            # insert this BuildList into U
            # DEBUG
            # print("writing BuildList with hash %s into %s" % (newHash, u_path))
            # END
            u_dir = UDir.discover(u_path)
            # DEBUG
            # print("listGen:")
            #print("  uDir:      %s" % u_path)
            #print("  dirStruc:  %s" % UDir.dirStrucToName(uDir.dirStruc))
            #print("  using_sha: %s" % uDir.using_sha)
            # END
            (length, hashBack) = u_dir.put_data(newData, newHash)
            if hashBack != newHash:
                print("WARNING: wrote %s to %s, but actual hash is %s" % (
                    newHash, u_path, hashBack))

        # CHANGES TO DATADIR AFTER UPDATING u_path ===================

        # serialize the BuildList, typically to .dvcz/lastBuildList
        with open(pathToListing, 'wb+') as file:
            file.write(newData)

        # DEBUG
        # print("hash of buildList at %s is %s" % (pathToListing, newHash))
        # END
        if logging:
            pathToLog = os.path.join(dvczDir, 'builds')
            with open(pathToLog, 'a') as file:
                file.write("%s v%s %s\n" % (bl.timestamp, version, newHash))

        return bl

    def populateDataDir(self, u_path, dataPath):
        # u_path path to U, including directory name
        # dataPath, path to dataDir, including directory name (which
        #   must be the same as the name of the tree)

        if not os.path.exists(u_path):
            raise RuntimeError("u_path %s does not exist" % u_path)

        relPath, junk, name = dataPath.rpartition('/')
        if name != self.tree.name:
            raise RuntimeError(
                "name mismatch: tree name %s but dataDir name %s" % (
                    self.tree.name, name))

        os.makedirs(relPath, exist_ok=True, mode=0o755)
        self.tree.populate_data_dir(u_path, relPath)

    # OTHER METHODS =================================================

    def check_in_data_dir(self, dataPath):
        """
        Whether the BuildList's component files are present in the
        data directory named.  Returns a list of content hashes for
        files not found.
        """
        return self.tree.check_in_data_dir(dataPath)

    def check_in_u_dir(self, u_path):
        """
        Whether the BuildList's component files are present in the
        U directory named.  Returns a list of content hashes for
        files not found.
        """
        return self.tree.check_in_u_dir(u_path)
