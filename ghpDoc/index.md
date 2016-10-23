<h1 class="libTop">buildlist</h1>

A set of Python3 utilities conforming to the
[BuildList](https://jddixon.github.io/xlattice/buildList.html)
specification and
intended to be interoperable with the Go
**builds/** package in
[xlCrypto_go](https://jddixon.github.com/xlCrypto_go)
as well as the Java version in
[xlCrypto.java](https://jddixon.github.com/xlCrypto_java).

## bl_bootStrap

A utility for use in testing the buildList package.  It generates a
directory tree, `example/` by default, in the current directory.  This
contains a data directory, `data_dir`; a corresponding BuildList,
`example.bld`; a secret key in `node`, and a matching content key
directory, `uDir`.  The distribution contains an SHA1 example directory
under `example1/` and an SHA256 directory as `example2/`.

	usage: bl_bootstrap [-h] [-e EXDIR] [-f] [-j] [-T] [-v]
	
	generate a sample data tree, write a build list, and create a corresponding
	content-keyed store
	
	optional arguments:
	  -h, --help            show this help message and exit
	  -e EXDIR, --exDir EXDIR
	                        example directory, defaults to example/
	  -f, --force           overwrite any existing example/ directory
	  -j, --just_show        show options and exit
	  -T, --testing         this is a test run
	  -v, --verbose         be chatty

## bl_check

This script runs an integrity check on a BuildList (`LISTFILE`) against
a given data directory (`DATADIR`) and content directory (`UDIR`).  The
BuildList file name and at least one of the data directory and content
directory must be present.

    usage: bl_check [-h] [-1] [-b LISTFILE] [-d DATADIR] [-i IGNOREFILE] [-j]
                   [-u UDIR] [-v]

    verify integrity of build list, optionally agains root dir and uDir"

    optional arguments:
      -h, --help            show this help message and exit
      -1, --using_sha1       using the 160-bit SHA1 hash
      -b LISTFILE, --list_file LISTFILE
                            root directory for build list
      -d DATADIR, --data_dir DATADIR
                            root directory for build list
      -i IGNOREFILE, --ignore_file IGNOREFILE
                            file containing wildcards (globs) for files to ignore
      -j, --just_show        show options and exit
      -u UDIR, --uDir UDIR  path to uDir
      -v, --verbose         be chatty

## bl_list_gen

Given a source directory specified by `-r`, writes a buildList to `LISTFILE`.

If the `-u` option is present, `UPATH` is a directory for the storage of files
by content key; `bl_list_gen` will copy each file in the build list into that
directory if the file is not already present.

It is usually important to skip some files, **not** adding them to the
buildList and the backup directory.  Such files are
specified with the `-X` option.

    usage: bl_list_gen [-h] [-1] [-b LISTFILE] [-D DVCZDIR] [-d DATADIR]
                     [-i IGNOREFILE] [-j] [-k KEYFILE] [-L] [-M MATCHPAT] [-T]
                     [-t TITLE] [-u UPATH] [-V] [-v] [-X EXCLUSIONS]

    generate build list for directory, optionally populating u_path

    optional arguments:
      -h, --help            show this help message and exit
      -1, --using_sha1       use SHA1 in building merkletree (default=false=use
                            SHA256)
      -b LISTFILE, --list_file LISTFILE
                            path to build list
      -D DVCZDIR, --dvcz_dir DVCZDIR
                            dvcz directory (default=.dvcz)
      -d DATADIR, --data_dir DATADIR
                            data directory for build list (default=./)
      -i IGNOREFILE, --ignore_file IGNOREFILE
                            file containing wildcards (globs) for files to ignore
      -j, --just_show        show options and exit
      -k KEYFILE, --key_file KEYFILE
                            path to RSA private key for signing
      -L, --logging         append timestamp and BuildList hash to to .dvcz/builds
      -M MATCHPAT, --matchPat MATCHPAT
                            include only files matching this pattern
      -T, --testing         this is a test run
      -t TITLE, --title TITLE
                            title for build list
      -u UPATH, --u_path UPATH
                            path to u_path (relative to tmp/ if testing)
      -V, --show_version     display version number and exit
      -v, --verbose         be chatty
      -X EXCLUSIONS, --exclusions EXCLUSIONS
                            do not include files/directories matching this pattern

## bl_src_gen

This utility is complementary to `bl_list_gen`: given a build list and
a backup directory indexed by content key, `bl_src_gen` will rebuild the
source directory.  This can be used, for example, to restore an earlier
version of a source tree or to switch to another branch.

    usage: bl_src_gen [-h] [-b LISTFILE] [-d DATADIR] [-f] [-j] [-k KEYFILE]
                    [-M MATCHON] [-T] [-u UPATH] [-V] [-v] [-X EXCLUSIONS]

    given a build list and uDir, regenerate the data directory

    optional arguments:
      -h, --help            show this help message and exit
      -b LISTFILE, --list_file LISTFILE
                            where to find the build list
      -d DATADIR, --data_dir DATADIR
                            where to write the new tree
      -f, --force           do it despite objections
      -j, --just_show        show options and exit
      -k KEYFILE, --key_file KEYFILE
                            path to RSA key for verifying dig sig
      -M MATCHON, --match_on MATCHON
                            include only files matching this pattern
      -T, --testing         this is a test run
      -u UPATH, --u_path UPATH
                            path to uDir (relative to tmp/ if testing)
      -V, --show_version     display version number and exit
      -v, --verbose         be chatty
      -X EXCLUSIONS, --exclusions EXCLUSIONS
                            do not include files/directories matching this pattern

## Project Status

A reasonable beta.

