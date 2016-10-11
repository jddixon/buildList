# buildList

A set of Python3 utilities conforming to the
[BuildList](https://jddixon.github.io/xlattice/buildList.html)
specification and
intended to be interoperable with the Go
**builds/** package in
[xlCrypto_go](https://jddixon.github.com/xlCrypto_go)
as well as the Java version in
[xlCrypto.java](https://jddixon.github.com/xlCrypto_java).

## blBootStrap

A utility for use in testing the buildList package.  It generates a
directory tree, `example/` by default, in the current directory.  This
contains a data directory, `dataDir`; a corresponding BuildList,
`example.bld`; a secret key in `node`, and a matching content key
directory, `uDir`.  The distribution contains an SHA1 example directory
under `example1/` and an SHA256 directory as `example2/`.

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

This script runs an integrity check on a BuildList (`LISTFILE`) against
a given data directory (`DATADIR`) and content directory (`UDIR`).  The
BuildList file name and at least one of the data directory and content
directory must be present.

    usage: blCheck [-h] [-1] [-b LISTFILE] [-d DATADIR] [-i IGNOREFILE] [-j]
                   [-u UDIR] [-v]

    verify integrity of build list, optionally agains root dir and uDir"

    optional arguments:
      -h, --help            show this help message and exit
      -1, --using_sha1       using the 160-bit SHA1 hash
      -b LISTFILE, --listFile LISTFILE
                            root directory for build list
      -d DATADIR, --dataDir DATADIR
                            root directory for build list
      -i IGNOREFILE, --ignoreFile IGNOREFILE
                            file containing wildcards (globs) for files to ignore
      -j, --justShow        show options and exit
      -u UDIR, --uDir UDIR  path to uDir
      -v, --verbose         be chatty

## blListGen

Given a source directory specified by `-r`, writes a buildList to `LISTFILE`.

If the `-u` option is present, `UPATH` is a directory for the storage of files
by content key; `blListGen` will copy each file in the build list into that
directory if the file is not already present.

It is usually important to skip some files, **not** adding them to the
buildList and the backup directory.  Such files are
specified with the `-X` option.

    usage: blListGen [-h] [-1] [-b LISTFILE] [-D DVCZDIR] [-d DATADIR]
                     [-i IGNOREFILE] [-j] [-k KEYFILE] [-L] [-M MATCHPAT] [-T]
                     [-t TITLE] [-u UPATH] [-V] [-v] [-X EXCLUSIONS]

    generate build list for directory, optionally populating uPath

    optional arguments:
      -h, --help            show this help message and exit
      -1, --using_sha1       use SHA1 in building merkletree (default=false=use
                            SHA256)
      -b LISTFILE, --listFile LISTFILE
                            path to build list
      -D DVCZDIR, --dvczDir DVCZDIR
                            dvcz directory (default=.dvcz)
      -d DATADIR, --dataDir DATADIR
                            data directory for build list (default=./)
      -i IGNOREFILE, --ignoreFile IGNOREFILE
                            file containing wildcards (globs) for files to ignore
      -j, --justShow        show options and exit
      -k KEYFILE, --keyFile KEYFILE
                            path to RSA private key for signing
      -L, --logging         append timestamp and BuildList hash to to .dvcz/builds
      -M MATCHPAT, --matchPat MATCHPAT
                            include only files matching this pattern
      -T, --testing         this is a test run
      -t TITLE, --title TITLE
                            title for build list
      -u UPATH, --uPath UPATH
                            path to uPath (relative to tmp/ if testing)
      -V, --showVersion     display version number and exit
      -v, --verbose         be chatty
      -X EXCLUSIONS, --exclusions EXCLUSIONS
                            do not include files/directories matching this pattern

## blSrcGen

This utility is complementary to `blListGen`: given a build list and
a backup directory indexed by content key, `blSrcGen` will rebuild the
source directory.  This can be used, for example, to restore an earlier
version of a source tree or to switch to another branch.

    usage: blSrcGen [-h] [-b LISTFILE] [-d DATADIR] [-f] [-j] [-k KEYFILE]
                    [-M MATCHON] [-T] [-u UPATH] [-V] [-v] [-X EXCLUSIONS]

    given a build list and uDir, regenerate the data directory

    optional arguments:
      -h, --help            show this help message and exit
      -b LISTFILE, --listFile LISTFILE
                            where to find the build list
      -d DATADIR, --dataDir DATADIR
                            where to write the new tree
      -f, --force           do it despite objections
      -j, --justShow        show options and exit
      -k KEYFILE, --keyFile KEYFILE
                            path to RSA key for verifying dig sig
      -M MATCHON, --matchOn MATCHON
                            include only files matching this pattern
      -T, --testing         this is a test run
      -u UPATH, --uPath UPATH
                            path to uDir (relative to tmp/ if testing)
      -V, --showVersion     display version number and exit
      -v, --verbose         be chatty
      -X EXCLUSIONS, --exclusions EXCLUSIONS
                            do not include files/directories matching this pattern

## Project Status

A reasonable beta.

## On-line Documentation

More information on the **buildList** project can be found
[here](https://jddixon.github.io/buildList)
