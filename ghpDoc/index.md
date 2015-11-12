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
* a file name followed by its content hash.
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
[NLHTree](http://jddixon.github.io/nlhtree).

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

## Project Status

A good beta.

## On-line Documentation
