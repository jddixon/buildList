# buildList

A set of Python3 utilities conforming to the
[BuildList](https://jddixon.github.io/xlattice/buildList.html)
specification and
intended to be interoperable with the
**builds/** package in
[xlCrypto_go](https://github.com/jddixon/xlCrypto_go).

## blBootStrap

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

## blCheck

	usage: blCheck [-h] [-1] [-b LISTFILE] [-j] [-r ROOTDIR] [-u UDIR] [-v]
	
	verify integrity of build list, optionally agains root dir and uDir"
	
	optional arguments:
	  -h, --help            show this help message and exit
	  -1, --usingSHA1       using the 160-bit SHA1 hash
	  -b LISTFILE, --listFile LISTFILE
	                        root directory for build list
	  -j, --justShow        show options and exit
	  -r ROOTDIR, --rootDir ROOTDIR
	                        root directory for build list
	  -u UDIR, --uDir UDIR  path to uDir
	  -v, --verbose         be chatty

## blListGen

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

## blSrcGen

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

## On-line Documentation

More information on the **buildList** project can be found
[here](https://jddixon.github.io/buildList)
