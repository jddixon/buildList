# buildlist/__init__.py

""" Object for verifying integrity of description of directory structure. """

import base64
import binascii
import calendar
import shutil
import sys
import time

import os
try:
    from os import scandir
except ImportError:
    from scandir import scandir

import hashlib
import sha3         # XXX should be conditional

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA, SHA256
from Crypto.Signature import PKCS1_PSS

from nlhtree import NLHNode, NLHTree, NLHLeaf

from xlattice.crypto import collect_pem_rsa_public_key
from xlattice.lfs import touch
from xlattice import HashTypes, check_hashtype
from xlattice.u import DirStruc, UDir
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
           'BLIntegrityCheckFailure', 'BLParseFailed', 'BLError', ]

__version__ = '0.9.0'
__version_date__ = '2017-01-18'

# UTILITY FUNCTIONS -------------------------------------------------


def check_dirs_in_path(path_to_file):
    """
    If a path to the file is specified, create intervening directories
    if they don't exist.
    """
    if path_to_file:
        dir_, _, _ = path_to_file.rpartition('/')
        if dir_:
            os.makedirs(dir_, 0o711, exist_ok=True)

# this should be in some common place ...


def rm_f_dir_contents(path_to_dir):
    """
    Equivalent to rm -rf.
    """
    if not path_to_dir:
        raise BLError('rm_f_dir_contents: directory must be named')
    if path_to_dir[0] == '/' or (path_to_dir.find('..') != -1):
        raise BLError(
            "illegal path for rm_f_dir_contents(): '%s'" % path_to_dir)
    for entry in scandir(path_to_dir):
        if entry.is_file():
            os.unlink(entry.path)
        elif entry.is_dir():
            shutil.rmtree(entry.path)
    # allow exceptions to bubble up

# RSA KEY PAIR ------------------------------------------------------


def generate_rsa_key(path_to_file, bit_count=2048):
    """
    Generate an RSA key and write it to disk in PEM format.  The key size
    should be no less than 1024 bits.
    """

    check_dirs_in_path(path_to_file)

    key = RSA.generate(bit_count)
    with open(path_to_file, 'wb+') as file:
        file.write(key.exportKey('PEM'))
    os.chmod(path_to_file, 0o600)


def read_rsa_key(path_to_file):
    """
    Read an RSA private key from disk.
    """
    with open(path_to_file, 'rb') as file:
        key = RSA.importKey(file.read())
    return key

# PARSER ------------------------------------------------------------


class BLIntegrityCheckFailure(RuntimeError):
    """ Report an integrity check failure parsing the BuildList. """
    pass


class BLParseFailed(RuntimeError):
    """ Report an error parsing the BuildList. """
    pass


def accept_list_line(file):
    """ Read the next line, drop any terminating character(s), and return. """
    line = file.readline()
    len_line = len(line)
    if len_line:
        if line.endswith(BuildList.NEWLINE):
            line = line[:len_line - 2]
        elif line.endswith(BuildList.NEWLINE):
            line = line[:len_line - 1]
        else:
            raise BLParseFailed("expected LF")
    return line


def expect_list_line(file, err_msg):
    """ Read the next line, raising if there isn't one. """
    line = accept_list_line(file)
    if not line:
        raise BLParseFailed(err_msg)
    return line


def expect_title(file, digest):
    """ Read the title line, adding it to the SHA hash. """

    line = expect_list_line(file, "missing title")
    # DEBUG
    # print("TITLE: %s" % line)
    # END
    digest.update(line)


def expect_timestamp(file, digest):
    """ Read the timestamp, adding it to the SHA hash. """

    line = expect_list_line(file, "missing timestamp")
    tstamp = parse_timestamp(line)        # can raise ValueError
    # DEBUG
    #print("TIMESTAMP: %s" % tstamp)
    # END
    digest.update(tstamp)


def expect_str(file, string):
    """ Raise an exception if the next line doesn't match string. """
    line = expect_list_line(file, "expected " + string)
    if line != string:
        raise BLParseFailed('expected ' + string)
    # DEBUG
    # print("STR: %s" % string)
    # END


def accept_content_line(file, digest, string, root_path, u_path):
    """
    Accept either a content line or a delimiter (string).  Anything else
    raises an exception.  Returns True if content line matched, False
    if delimiter detected; otherwise raises a BLParseFailed.

    NOT IMPLEMENTED: If root_path is not None, compares the content hash
    with that of the file at the relative path.

    NOT IMPLEMENTED: If u_path is not None, verifies that the content key
    matches that of a file present in u_path.
    """
    line = accept_list_line(file)        # may raise BLParseFailed
    if line == string:
        # DEBUG
        # print("STR: " + line)
        # END
        return False

    # Parse the content line
    parts = line.split()
    if len(parts) != 2:
        err_msg = "bad content line: '%s'" % line
        raise BLParseFailed(err_msg)
    # DEBUG
    # print("CONTENT: %s" % line)
    # END
    digest.update(line)
    b64hash = parts[0]
    path = parts[1]

    # XXX NO CHECK AGAINST root_path
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
    NEWLINE = '\n'.encode('utf-8')

    # XXX DROP by v1.0.0
    OLD_CONTENT_START = '# START CONTENT #'
    # XXX END DROP

    def __init__(self, title, sk_, tree):

        self._title = title.strip()
        # pylint: disable=protected-access
        if (not sk_) or (not isinstance(sk_, RSA._RSAobj)):
            raise BLError("sk is nil or not a valid RSA public key")
        self._public_key = sk_

        if (not tree) or (not isinstance(tree, NLHTree)):
            raise BLError('tree is nil or not a valid NLHTree')

        self._tree = tree

        # -----------------------------------------------------------
        # considere adding another constructor instead of setters for
        # _when and _dig_sig
        # -----------------------------------------------------------
        self._when = 0         # seconds from the Epoch; a 64-bit value
        self._dig_sig = None
        self._ex_re = None

    @property
    def dig_sig(self):
        """
        Take care: we store the binary value but this returns it
        base64-encoded.
        """
        if self._dig_sig is None:
            return None
        else:
            return base64.b64encode(self._dig_sig).decode('utf-8')

    @dig_sig.setter
    def dig_sig(self, value):
        """
        Set the digital signature if it is not already set.
        """
        if self._dig_sig is None:
            self._dig_sig = value
        else:
            raise BLError("BuildList is already signed")

    @property
    def ex_re(self):
        return self._ex_re

    @property
    def public_key(self):
        return self._public_key

    @property
    def signed(self):
        return self._dig_sig is not None

    @property
    def timestamp(self):
        return timestamp(self._when)

    @property
    def title(self):
        return self._title

    @property
    def tree(self):
        return self._tree

    @property
    def hashtype(self):
        return self._tree.hashtype

    @property
    def when(self):
        return self._when

    @when.setter
    def when(self, value):
        # Xxx validation
        self._when = value

    def _get_build_list_sha1(self):
        sha = SHA.new()
        # add public key and then LF to hash
        pem_ck = self._public_key.exportKey('PEM')
        sha.update(pem_ck)
        sha.update(BuildList.NEWLINE)

        # add title and LF to hash
        sha.update(self._title.encode('utf-8'))
        sha.update(BuildList.NEWLINE)

        # add timestamp and LF to hash
        sha.update(self.timestamp.encode('utf-8'))
        sha.update(BuildList.NEWLINE)

        # add CONTENT_START and LF line to hash
        sha.update((BuildList.CONTENT_START + '\n').encode('utf-8'))

        # add serialized NLHTree to hash, each line terminated by LF
        sha.update(self._tree.__str__().encode('utf-8'))

        # add CONTENT_END and LF line to hash
        sha.update((BuildList.CONTENT_END + '\n').encode('utf-8'))

        # add LF to hash
        sha.update(BuildList.NEWLINE)
        return sha

    def sign(self, sk_priv):
        """
        Sign the BuildList using the RSA private key.

        sk_priv is the RSA private key used for siging the BuildList.
        """

        if self._dig_sig is not None:
            raise BLError("buildlist has already been signed")

        # Verify that the public key (sk) is the public part of sk_priv,
        # the private RSA key.
        if (not sk_priv) or (not isinstance(sk_priv, RSA._RSAobj)):
            raise BLError("sk_priv is nil or not a valid RSA key")
        if sk_priv.publickey() != self._public_key:
            raise BLError("sk_priv does not match BuildList's public key")

        # the time is part of what is signed, so we need to set it now
        # XXX truncating loses microseconds
        now = int(time.time())      # seconds from Epoch
        self._when = now

        sha = self._get_build_list_sha1()

        # Sign the list using SHA1 and RSA.  What we are signing is the
        # in-memory binary data structure.
        signer = PKCS1_PSS.new(sk_priv)
        self._dig_sig = signer.sign(sha)

    def verify(self):
        """
        Check that the BuildList is signed and the signature is correct.

        Return True if self._signature is set and it is
        consistent as an RSA-SHA1 with the public key on the
        document and the SHA1 hash of the serialized document, taking
        the hash over the fields in standard order (pubkey, title,
        timestamp, and content lines).
        """
        success = False

        if self._dig_sig:

            sha = self._get_build_list_sha1()
            verifier = PKCS1_PSS.new(self.public_key)
            success = verifier.verify(sha, self._dig_sig)

        return success

    # EQUALITY ------------------------------------------------------
    def __eq__(self, other):
        # DEBUG
        # print("entering BuildList.__eq__")
        # END
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
        if self.public_key != other.public_key:
            return False
        if not self.tree == other.tree:
            # DEBUG
            # print("NLHTrees differ")
            # END
            return False
        if self._when != other.when:
            print(
                "  my when = %f, other when = %f" %
                (self._when, other.when))
            return False

        if self._dig_sig is None:
            return other.dig_sig is None
        else:
            # DEBUG
            #           print("COMPARING DIG SIGS:\nDIG SIG A:\n%s" % self.dig_sig)
            #           print("DIG SIG B:\n%s" % other.dig_sig)
            # END
            return self.dig_sig == other.dig_sig

    # SERIALIZATION -------------------------------------------------
    @staticmethod
    def create_from_file_system(title, path_to_dir, sk_,
                                hashtype=HashTypes.SHA2,
                                ex_re=None, match_re=None):

        if (not path_to_dir) or (not os.path.isdir(path_to_dir)):
            raise BLError(
                "%s does not exist or is not a directory" % path_to_dir)

        tree = NLHTree.create_from_file_system(path_to_dir,
                                               # accept default deltaIndent
                                               hashtype=hashtype, ex_re=ex_re)
        return BuildList(title, sk_, tree)

    @staticmethod
    def parse(string, hashtype):
        """
        This relies upon the fact that all fields are separated by
        NEWLINE ('\n').
        """

        if string is None:
            raise BLParseFailed('BuildList.parse: empty input')
        if not isinstance(string, str):
            string = str(string, 'utf-8')
        strings = string.split('\n')
        return BuildList.parse_from_strings(strings, hashtype)

    @staticmethod
    def _expect_field(strings, ndx):
        """
        Complain if the Nth field does not exist.  Return the index
        of the next field.
        """
        if ndx >= len(strings):
            raise BLParseFailed("Missing %d-th field in BuildList")
        field = strings[ndx]
        ndx += 1
        return field, ndx

    @staticmethod
    def parse_from_strings(strings, hashtype):

        check_hashtype(hashtype)

        # DEBUG
        # print("parse_from_strings: hashtype = %s" % hashtype)
        # END
        if strings is None:
            raise BLParseFailed("parse_from_strings: null argument")

        # expect a PEM-encoded public key with embedded newlines
        first_line = strings[0]
        strings = strings[1:]
        ser_ck, strings = collect_pem_rsa_public_key(first_line, strings)
        my_ck = RSA.importKey(ser_ck)

        ndx = 0

        # expect a title
        my_title, ndx = BuildList._expect_field(strings, ndx)

        # expect a timestamp
        my_timestamp, ndx = BuildList._expect_field(strings, ndx)

        # expect CONTENT-START
        start_line, ndx = BuildList._expect_field(strings, ndx)
        if (start_line != BuildList.CONTENT_START) and\
                (start_line != BuildList.OLD_CONTENT_START):
            # DEBUG
            # print("Expected CONTENT START, got '%s'" % start_line)
            # END
            raise BLParseFailed("expected BEGIN CONTENT line")

        # expect a serialized NLHTree followed by a CONTENT END
        mt_lines = []
        while True:
            line, ndx = BuildList._expect_field(strings, ndx)
            if line == BuildList.CONTENT_END:
                break
            else:
                mt_lines.append(line)
        # expect default indents
        my_tree = NLHTree.create_from_string_array(mt_lines, hashtype)

        # expect an empty line
        space, _ = BuildList._expect_field(strings, ndx)
        if space != '':
            raise BLParseFailed("expected an empty line")
        ndx += 1

        # accept a digital signature if it is present
        if ndx < len(strings):
            my_dig_sig = strings[ndx]

        bld = BuildList(my_title, my_ck, my_tree)
        bld.when = parse_timestamp(my_timestamp)
        if my_dig_sig:
            bld.dig_sig = binascii.a2b_base64(my_dig_sig)
        return bld

    def __str__(self):
        return self.to_string()

    def to_string(self):
        """
        In this serialization, each field appears followed by a CR-LF
        sequence.
        """
        strings = self.to_strings()
        return '\n'.join(strings)

    def to_strings(self):
        strings = []

        # public key (with embedded newlines)
        pem_ck = self.public_key.exportKey('PEM').decode('utf-8')
        strings.append(pem_ck)

        # title
        strings.append(self.title)

        # timestamp
        strings.append(self.timestamp)

        # content start line
        strings.append(BuildList.CONTENT_START)

        # NLHTree
        # XXX use self.tree.to_strings and then extend(), yes ?
        tree_lines = self.tree.__str__().split('\n')
        if (len(tree_lines) > 1) and (tree_lines[-1] == ''):
            tree_lines = tree_lines[0:-1]
        strings += tree_lines

        # content end line
        strings.append(BuildList.CONTENT_END)

        # empty line
        strings.append('')

        # dig sig
        if self._dig_sig:
            strings.append(self.dig_sig)

        return strings

    # OTHER CONSTRUCTORS --------------------------------------------

    @classmethod
    def list_gen(cls, title, data_dir,
                 dvcz_dir='.dvcz',
                 list_file='lastBuildList',
                 key_file=os.path.join(
                     os.environ['DVCZ_PATH_TO_KEYS'], 'skPriv.pem'),
                 excl=['build'],
                 logging=False,
                 u_path='',
                 hashtype=HashTypes.SHA1):     # NOTE default is SHA1
        """
        Create a BuildList for data_dir with the title indicated.
        Files matching the globs in excl will be skipped.  'build'
        should always be in the list.  If a private key is specified
        and signing is True, the BuildList will be digitally signed.
        If u_path is specified, the files in data_dir will be posted to uDir.
        By default SHA1 hash will be used for the digital
        signature.

        If there is a title, we try to read the version number from
        the first line of .dvcz/version.  If that exists, we append
        a space and then the version number to the title.
        """
        version = '0.0.0'
        path_to_version = os.path.join(dvcz_dir, 'version')
        if os.path.exists(path_to_version):
            with open(path_to_version, 'r') as file:
                version = file.readline().strip()
                title = title + ' v' + version
                # DEBUG
                # print("title with version is '%s'" % title)
                # END

        ex_re = make_ex_re(excl)
        signing = key_file != ''
        if signing:
            with open(key_file, 'r') as file:
                sk_priv = RSA.importKey(file.read())
            sk_ = sk_priv.publickey()
        else:
            sk_ = None
        blist = cls.create_from_file_system(
            title, data_dir, sk_, hashtype, ex_re, match_re=None)
        if signing:
            blist.sign(sk_priv)

        new_data = blist.__str__().encode('utf-8')
        # pylint:disable=redefined-variable-type
        if hashtype == HashTypes.SHA1:
            sha = hashlib.sha1()
        elif hashtype == HashTypes.SHA2:
            sha = hashlib.sha256()
        elif hashtype == HashTypes.SHA3:
            sha = hashlib.sha3_256()
        sha.update(new_data)
        new_hash = sha.hexdigest()
        path_to_listing = os.path.join(dvcz_dir, list_file)

        if u_path:

            blist.tree.save_to_u_dir(data_dir, u_path, hashtype)

            # insert this BuildList into U
            # DEBUG
            # print("writing BuildList with hash %s into %s" % (new_hash, u_path))
            # END
            u_dir = UDir.discover(u_path)
            # DEBUG
            # print("list_gen:")
            #print("  uDir:      %s" % u_path)
            #print("  dirStruc:  %s" % UDir.dir_struc_to_name(uDir.dirStruc))
            #print("  hashtype:  %s" % uDir.hashtype)
            # END
            (_, hash_back) = u_dir.put_data(new_data, new_hash)
            if hash_back != new_hash:
                print("WARNING: wrote %s to %s, but actual hash is %s" % (
                    new_hash, u_path, hash_back))

        # CHANGES TO DATADIR AFTER UPDATING u_path ===================

        # serialize the BuildList, typically to .dvcz/lastBuildList
        with open(path_to_listing, 'wb+') as file:
            file.write(new_data)

        # DEBUG
        # print("hash of buildlist at %s is %s" % (path_to_listing, new_hash))
        # END
        if logging:
            path_to_log = os.path.join(dvcz_dir, 'builds')
            with open(path_to_log, 'a') as file:
                file.write("%s v%s %s\n" %
                           (blist.timestamp, version, new_hash))

        return blist

    def populate_data_dir(self, u_path, data_path):
        # u_path path to U, including directory name
        # data_path, path to data_dir, including directory name (which
        #   must be the same as the name of the tree)

        if not os.path.exists(u_path):
            raise RuntimeError("u_path %s does not exist" % u_path)

        rel_path, _, name = data_path.rpartition('/')
        if name != self.tree.name:
            raise RuntimeError(
                "name mismatch: tree name %s but data_dir name %s" % (
                    self.tree.name, name))

        os.makedirs(rel_path, exist_ok=True, mode=0o755)
        self.tree.populate_data_dir(u_path, rel_path)

    # OTHER METHODS =================================================

    def check_in_data_dir(self, data_path):
        """
        Whether the BuildList's component files are present in the
        data directory named.  Returns a list of content hashes for
        files not found.
        """
        return self.tree.check_in_data_dir(data_path)

    def check_in_u_dir(self, u_path):
        """
        Whether the BuildList's component files are present in the
        U directory named.  Returns a list of content hashes for
        files not found.
        """
        return self.tree.check_in_u_dir(u_path)
