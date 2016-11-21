# buildlist

A set of Python3 utilities conforming to the
[BuildList](https://jddixon.github.io/xlattice/buildList.html)
specification and
intended to be interoperable with the Go
**builds/** package in
[xlCrypto_go](https://jddixon.github.com/xlCrypto_go)
as well as the Java version in
[xlCrypto.java](https://jddixon.github.com/xlCrypto_java).

## bl_bootstrap

A utility for use in testing the buildlist package.  It generates a
directory tree, `example/` by default, in the current directory.  This
contains a data directory, `dataDir`; a corresponding BuildList,
`example.bld`; a secret key in `node`, and a matching content key
directory, `uDir`.  The distribution contains an SHA1 example directory
under `example1/` and an SHA256 directory as `example2/`.

    usage: bl_bootstrap [-h] [-e EX_DIR] [-f] [-j] [-v]

    generate a sample data tree, write a build list, and create a corresponding
    content-keyed store

    optional arguments:
      -h, --help            show this help message and exit
      -e EX_DIR, --ex_dir EX_DIR
                            example directory, defaults to example/
      -f, --force           overwrite any existing example/ directory
      -j, --just_show       show options and exit
      -v, --verbose         be chatty

## bl_check

This script runs an integrity check on a BuildList (`LISTFILE`) against
a given data directory (`DATADIR`) and content directory (`UDIR`).  The
BuildList file name and at least one of the data directory and content
directory must be present.

    usage: bl_check [-h] [-b LIST_FILE] [-d DATA_DIR] [-i IGNORE_FILE] [-j] [-1]
                    [-2] [-3] [-u U_PATH] [-v]

    verify integrity of build list, optionally agains root dir and u_path"

    optional arguments:
      -h, --help            show this help message and exit
      -b LIST_FILE, --list_file LIST_FILE
                            root directory for build list
      -d DATA_DIR, --data_dir DATA_DIR
                            root directory for build list
      -i IGNORE_FILE, --ignore_file IGNORE_FILE
                            file containing wildcards (globs) for files to ignore
      -j, --just_show       show options and exit
      -1, --using_sha1      using the 160-bit SHA1 hash
      -2, --using_sha2      using the 256-bit SHA2 (SHA256) hash
      -3, --using_sha3      using the 256-bit SHA3 (Keccak-256) hash
      -u U_PATH, --u_path U_PATH
                            path to uDir
      -v, --verbose         be chatty

## bl_createtestdata1

Create test data for
[https://github.com/jddixon/xl_test_data](https://github.com/jddixon/xl_test_data).

The test data is intended for testing interoperability between various
gibhub probjects using different computer languages, specifically Python
and Go in the shorter term.  Data consists of a random directory structure
containing raw data files of random length and then corresponding

* NLHTrees
* BuildLists
* content-keyed stores using SHA{1,2,3} structured as flat, 16x16, and 256x256

Replaces `bl_bootstrap`.  Output is to the xl_test_data project directory.

    usage: bl_createtestdata1 [-h] [-f] [-j] [-o OUT_PATH] [-v]

    generate a sample data tree, write a build list, and create a corresponding
    content-keyed store

    optional arguments:
      -h, --help            show this help message and exit
      -f, --force           overwrite any existing example/ directory
      -j, --justShow        show options and exit
      -o OUT_PATH, --out_path OUT_PATH
                            example directory, defaults to
                            '../../dat/xl_test_data/treeData/binExample_1'
      -v, --verbose         be chatty

## bl_listgen

Given a source directory specified by `-r`, writes a buildlist to `LISTFILE`.

If the `-u` option is present, `UPATH` is a directory for the storage of files
by content key; `blListGen` will copy each file in the build list into that
directory if the file is not already present.

It is usually important to skip some files, **not** adding them to the
buildlist and the backup directory.  Such files are
specified with the `-X` option.

    usage: bl_listgen [-h] [-b LIST_FILE] [-D DVCZ_DIR] [-d DATA_DIR]
                       [-i IGNORE_FILE] [-j] [-k KEY_FILE] [-L] [-M MATCHPAT] [-T]
                       [-t TITLE] [-V] [-1] [-2] [-3] [-u U_PATH] [-v]
                       [-X EXCLUSIONS]

    generate build list for directory, optionally populating u_path

    optional arguments:
      -h, --help            show this help message and exit
      -b LIST_FILE, --list_file LIST_FILE
                            path to build list
      -D DVCZ_DIR, --dvcz_dir DVCZ_DIR
                            dvcz directory (default=.dvcz)
      -d DATA_DIR, --data_dir DATA_DIR
                            data directory for build list (default=./)
      -i IGNORE_FILE, --ignore_file IGNORE_FILE
                            file containing wildcards (globs) for files to ignore
      -j, --just_show       show options and exit
      -k KEY_FILE, --key_file KEY_FILE
                            path to RSA private key for signing
      -L, --logging         append timestamp and BuildList hash to to .dvcz/builds
      -M MATCHPAT, --matchPat MATCHPAT
                            include only files matching this pattern
      -T, --testing         this is a test run
      -t TITLE, --title TITLE
                            title for build list
      -V, --showVersion     display version number and exit
      -1, --using_sha1      using the 160-bit SHA1 hash
      -2, --using_sha2      using the 256-bit SHA2 (SHA256) hash
      -3, --using_sha3      using the 256-bit SHA3 (Keccak-256) hash
      -u U_PATH, --u_path U_PATH
                            path to uDir
      -v, --verbose         be chatty
      -X EXCLUSIONS, --exclusions EXCLUSIONS
                            do not include files/directories matching this pattern

## bl_srcgen

This utility is complementary to `blListGen`: given a build list and
a backup directory indexed by content key, `blSrcGen` will rebuild the
source directory.  This can be used, for example, to restore an earlier
version of a source tree or to switch to another branch.

    usage: bl_srcgen [-h] [-b LIST_FILE] [-d DATA_DIR] [-f] [-j] [-k KEY_FILE]
                      [-M MATCH_ON] [-T] [-u U_PATH] [-V] [-v] [-X EXCLUSIONS]

    given a build list and uDir, regenerate the data directory

    optional arguments:
      -h, --help            show this help message and exit
      -b LIST_FILE, --list_file LIST_FILE
                            where to find the build list
      -d DATA_DIR, --data_dir DATA_DIR
                            where to write the new tree
      -f, --force           do it despite objections
      -j, --just_show       show options and exit
      -k KEY_FILE, --key_file KEY_FILE
                            path to RSA key for verifying dig sig
      -M MATCH_ON, --match_on MATCH_ON
                            include only files matching this pattern
      -T, --testing         this is a test run
      -u U_PATH, --u_path U_PATH
                            path to uDir (relative to tmp/ if testing)
      -V, --show_version    display version number and exit
      -v, --verbose         be chatty
      -X EXCLUSIONS, --exclusions EXCLUSIONS
                            do not include files/directories matching this pattern


## Project Status

A reasonable beta.

## On-line Documentation

More information on the **buildlist** project can be found
[here](https://jddixon.github.io/buildlist)
