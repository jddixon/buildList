<h1 class="libTop">buildList</h1>

A set of Python utilities intended to be interoperable with the
**builds/** package in https://github.com/jddixon/xlCrypto_go.

## Serialization

In its serialized form a BuildList consists of

* a public key line,
* a title line,
* a timestamp line,
* a number of content lines, and
* optionally a digital signature.

Each of the lines ends with a linefeed (a byte with the value 10,
conventionally written as `\\n`).

A blank line follows the last content line.  The timestamp (in
CCYY-MM-DD HH:MM:SS form) represents the time at which the list
was signed using the RSA private key corresponding to the key in
the public key line.  The public key itself is base-64 encoded.

## Content Lines

The content lines section begins and ends with fixed `# BEGIN CONTENT #`
and `# END CONTENT #` delimiters.  Each actual content line consists of

* either a directory name or
* a file name followed by its content hash written as a hexadecimal string

In either case the name
is indented by a number of spaces equivalent to its depth in the hierarchy.

	# BEGIN CONTENT #
	dir1
	 fileForHash0 0123456789012345678901234567890123456789
	 fileForHash1 abcdef0123456789abcdef0123456789abcdef01
	 dir11
	  fileForHash2 12abcdef0123456789abcdef0123456789abcdef
	  fileForHash3 3456abcdef0123456789abcdef0123456789abcd
	# END CONTENT #

That is, the data structure between the BEGIN/END CONTENT lines is an
[NLHTree](http://jddixon.github.io/nlhtree_py).

## Digital Signature

The SHA1withRSA digital signature is over the entire SignedList excluding
the digital signature line and the blank line preceding it.  All line
endings are converted to LF (`\\n`) before taking the digital signature.

## Extended Hash

The BuildList itself has a 20-byte extended hash, the 20-byte SHA1
digest of a function of the public key and the title.  This means
that the owner of the RSA key can create any number of documents
with the same hash but different timestamps with the intention
being that users can choose to regard the document with the most
recent timestamp as current.

## Utilities

### blBootStrap

A utility for use in testing the buildList package.

	usage: blBootstrap [-h] [-e EXDIR] [-f] [-j] [-T] [-v]
	
	generate a sample data tree, write a build list, and create a corresponding
	content-keyed store
	
	optional arguments:
	  -h, --help            show this help message and exit
	  -e EXDIR, --exDir EXDIR
	                        example directory, defaults to example/
	  -f, --force           overwrite any existing example/ directory
	  -j, --justShow        show options and exit
	  -T, --testing         this is a test run
	  -v, --verbose         be chatty

### blListGen

Given a source directory specified by `-r`, writes a buildList to `listFile`.

If the `-u` option is present, that is a directory for the storage of files
by content key; `blListGen` will copy each file in the build list into that
directory if it is not already present.

It is usually important to skip some files, **not** adding them to the
buildList and the backup directory; such files are
specified with the `-X` option.

	usage: blListGen [-h] [-1] [-b LISTFILE] [-j] [-k KEYFILE] [-P MATCHPAT]
	                 [-r ROOTDIR] [-s] [-T] [-t TITLE] [-u UDIR] [-v] [-X EXCLUDE]
	
	generate build list for directory, optionally populating uDir
	
	optional arguments:
	  -h, --help            show this help message and exit
	  -1, --usingSHA1       use SHA1 in building merkletree (default=false=use
	                        SHA256)
	  -b LISTFILE, --listFile LISTFILE
	                        path to build list
	  -j, --justShow        show options and exit
	  -k KEYFILE, --keyFile KEYFILE
	                        path to RSA private key for signing
	  -P MATCHPAT, --matchPat MATCHPAT
	                        include only files matching this pattern
	  -r ROOTDIR, --rootDir ROOTDIR
	                        root directory for build list (REQUIRED)
	  -s, --signing         digitally sign the generated BuildList
	  -T, --testing         this is a test run
	  -t TITLE, --title TITLE
	                        title for build list
	  -u UDIR, --uDir UDIR  path to uDir (relative to tmp/ if testing)
	  -v, --verbose         be chatty
	  -X EXCLUDE, --exclude EXCLUDE
	                        exclude files matching this pattern

### blSrcGen

This utility is complementary to `blListGen`: given a build list and
a backup directory indexed by content key, `blSrcGen` will rebuild the
source directory.  This can be used, for example, to restore an earlier
version of a source tree or to switch to another branch.

	usage: blSrcGen [-h] [-b LISTFILE] [-f] [-j] [-r ROOTDIR] [-T] [-t TITLE]
	                [-u UDIR] [-v]
	
	given a build list and uDir, regenerate the root directory
	
	optional arguments:
	  -h, --help            show this help message and exit
	  -b LISTFILE, --listFile LISTFILE
	                        root directory for build list
	  -f, --force           do it despite objections
	  -j, --justShow        show options and exit
	  -r ROOTDIR, --rootDir ROOTDIR
	                        root directory for build list (REQUIRED)
	  -T, --testing         this is a test run
	  -t TITLE, --title TITLE
	                        title for build list
	  -u UDIR, --uDir UDIR  path to uDir (relative to tmp/ if testing)
	  -v, --verbose         be chatty

## Project Status

A good beta.

