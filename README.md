# buildList

A set of Python utilities intended to be interoperable with the
**builds/** package in https://github.com/jddixon/xlCrypto_go.

## Serialization

In its serialized form a BuildList consists of a public key line,
a title line, a timestamp line, a number of content lines, and a
digital signature.  Each of the lines ends with a CR-LF sequence.
A blank line follows the last content line.  The timestamp (in
CCYY-MM-DD HH:MM:SS form) represents the time at which the list
was signed using the RSA private key corresponding to the key in
the public key line.  The public key itself is base-64 encoded.  

## Content Lines

The content lines section begins and ends with fixed `# BEGIN CONTENT #` 
and `# END CONTENT #` delimiters.  Each line contains the base64-encoded
SHA1 hash of a file follows by a single space and then the path to the file.
Every line, including the delimiting lines, is terminated by a CR-LF sequence.

	# BEGIN CONTENT #
	CmexcHeMLrchiUg2SARuyKGqhsQ= fileForHash0
	a/UaOldRJxEvoaHpTLDC7TJZKWg= fileForHash1
	6AExKQ3f+WHUnJH40dysyEPmI/w= fileForHash2
	OrNHyszHbR7HM9FO/1evdK2i0YU= fileForHash3
	# END CONTENT #

## Digital Signature

The SHA1withRSA digital signature is on the entire SignedList excluding 
the digital signature line and the blank line preceding it.  All line 
endings are converted to CRLF before taking the digital signature.

## Extended Hash

The BuildList itself has a 20-byte extended hash, the 20-byte SHA1 
digest of a function of the public key and the title.  This means
that the owner of the RSA key can create any number of documents
with the same hash but different timestamps with the intention 
being that users can choose to regard the document with the most
recent timestamp as authentic.

## On-line Documentation

More information on the **buildList** project can be found 
[here](https://jddixon.github.io/buildList)
