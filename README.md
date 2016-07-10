# jsSHA
A JavaScript implementation of the complete Secure Hash Standard family
(SHA-1, SHA-224, SHA3-224, SHA-256, SHA3-256, SHA-384, SHA3-384, SHA-512,
SHA3-512, SHAKE128, and SHAKE256) as well as HMAC by Brian Turek.

[![Build Status](https://travis-ci.org/Caligatio/jsSHA.svg?branch=master)](https://travis-ci.org/Caligatio/jsSHA)

## About
jsSHA is a javaScript implementation of the complete Secure Hash Algorithm
family as defined by
[FIPS PUB 180-4](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) and
[FIPS PUB 202](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf).  It also
includes the HMAC algorithm with SHA support as defined by
[FIPS PUB 198-1](http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf).

## Files
**src/sha\_dev.js**

A commented implementation of the entire SHA family of hashes. Not to be used
in production.

**src/sha.js**

A Google Closure Compiler optimized version of the entire library.

**src/sha1.js**

A Google Closure Compiler optimized version the library with non SHA-1
functionality removed.

**src/sha256.js**

A Google Closure Compiler optimized version the library with non SHA-224/SHA-256
functionality removed.

**src/sha3.js**

A Google Closure Compiler optimized version the library with non SHA-3
functionality removed.

**src/sha512.js**

A Google Closure Compiler optimized version the library with non SHA-384/SHA-512
functionality removed.

**test/test.html**

Mocha/Chai test page that runs all the tests.

**test/genHashRounds.py**

A Python2 script that generates multi-round hash values.

**test/genShake.py**

A Python2 script that generates SHAKE hash values.

**test/sha3.py**

A Python reference implementation of the SHA3 family of hashes.

**build/make-release**

A Bash script that runs the various Google Closure Compiler commands to build
a release.

**build/externs.js**

File needed solely to make the Google Closure Compilter work.

## Usage

### Browser
Include the desired JavaScript file (sha.js, sha1.js, sha256.js, sha512.js, or
sha3.js) in your header (sha.js used below):

	<script type="text/javascript" src="/path/to/sha.js"></script>

#### Hashing
Instantiate a new jsSHA object with the desired hash type, input type, and
options as parameters.  The hash type can be one of SHA-1, SHA-224, SHA3-224,
SHA-256, SHA3-256, SHA-384, SHA3-384, SHA-512, SHA3-512, SHAKE128, or SHAKE256.
The input type can be one of HEX, TEXT, B64, BYTES, or ARRAYBUFFER.  You can
then stream in input using the `update` object function.  Finally, simply call
`getHash` with the output type as a parameter (B64, HEX, BYTES, or ARRAYBUFFER).
Example to calculate the SHA-512 of "This is a test":

	var shaObj = new jsSHA("SHA-512", "TEXT");
	shaObj.update("This is a test");
	var hash = shaObj.getHash("HEX");

The constructor takes a hashmap as a optional third argument with possible
properties of `numRounds` and `encoding`.  `numRounds` controls the number of
hashing iterations/rounds performed and defaults to a value of 1 if not
specified. `encoding` specifies the encoding used to encode TEXT-type inputs.
Valid options are "UTF8", "UTF16BE", and "UTF16LE", it defaults to "UTF8".

`getHash` also takes a hashmap as an optional second argument.  By default the
hashmap is `{"outputUpper" : false, "b64Pad" : "="}`.  These options are
intelligently interpreted based upon the chosen output format. **Important**: 
SHAKE128 and SHAKE256 require `shakeLen` to be included in the hashmap where
`shakeLen` is the desired output length of the SHAKE algorithm in a multiple
of 8 bits.

#### HMAC
Instantiate a new jsSHA object the same way as for hashing.  Then set the HMAC
key to be used by calling `setHMACKey` with the key and its input type (this
MUST be done before calling update).  You can stream in the input using the
`update` object function just like hashing.  Finally, get the HMAC by calling
the `getHMAC` function with the output type as its argument.  Example to
calculate the SHA-512 HMAC of the string "This is a test" with the key "abc":

	var shaObj = new jsSHA(hashType, "TEXT");
	shaObj.setHMACKey("abc", "TEXT");
	shaObj.update("This is a test");
	var hmac = shaObj.getHMAC("HEX");

`setHMACKey` takes the same input types as the constructor and `getHMAC` takes the
same inputs as `getHash` as described above.

Note: You cannot calculate both the hash and HMAC using the same object.

### Node.js
jsSHA is available through NPM and be installed by simply doing

	npm install jssha
To use the module, first require it using:

	jsSHA = require("jssha");

The rest of the instructions are identical to the [Browser](#browser) section above.

## Compiling
This library makes use of the [Google Closure Compiler](https://developers.google.com/closure/compiler)
to both boost performance and reduce filesizes.  To compile sha\_dev.js into a customized output file,
use a command like the following:

	java -jar compiler.jar --define="SUPPORTED_ALGS=<FLAG>" \
		--externs /path/to/build/externs.js --warning_level VERBOSE \
		--compilation_level ADVANCED_OPTIMIZATIONS \
		--js /path/to/sha_dev.js --js_output_file /path/to/sha.js

where FLAG is a bitwise OR of the following values:

* 8 for SHA3
* 4 for SHA-384/SHA-512
* 2 for SHA-224/256
* 1 for SHA-1

## Contact Info
The project's website is located at [http://caligatio.github.com/jsSHA/](http://caligatio.github.com/jsSHA/)

## Donations
Feel like donating?  We're now accepting donations [through Pledgie](https://pledgie.com/campaigns/31646)!
