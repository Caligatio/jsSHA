# jsSHA
A JavaScript implementation of the complete Secure Hash Standard family
		(SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512) as well as HMAC by
		Brian Turek

About
-------------------------
jsSHA is a javaScript implementation of the complete Secure Hash Algorithm
family as defined by FIPS PUB 180-2
(http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf).

It also includes the HMAC algorithm with SHA support as defined by FIPS PUB 198-1
(http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf)

With the slow phasing out of MD5 as the standard hash to use in web
applications, a client-side implementation of the complete Secure Hash Standard
family was needed.  Due to SHA-384 and SHA-512's use of 64-bit values throughout
the algorithm, JavaScript can not easily natively support the calculation of
these hashes.  As a result, a bit of hacking had to be done to make sure the
values behaved themselves. SHA-224 was added to the Secure Hash Standard family
on 25 February 2004 so it was also included in this package.

Files
-------------------------
**src/sha_dev.js**

A commented implementation of the entire SHA family of hashes. Not to be used
in production.

**src/sha.js**

A Google Closure Compiler optimized version of the entire library

**src/sha1.js**

A Google Closure Compiler optimized version the library with non SHA-1
functionality removed

**src/sha256.js**

A Google Closure Compiler optimized version the library with non SHA-224/SHA-256
functionality removed

**src/sha512.js**

A Google Closure Compiler optimized version the library with non SHA-384/SHA-512
functionality removed

**test/test.html**

A test page that calculates various hashes and has their correct values

**build/make-release**

A Bash script that runs the various Google Closure Compiler commands to build
a release

Usage
-------------------------
Include the desired JavaScript file (sha.js, sha1.js, sha256.js, or sha512.js)
in your header (sha.js used below):

	<script type="text/javascript" src="/path/to/sha.js"></script>

Instantiate a new jsSHA object with your string to be hashed and its format
(HEX or TEXT) as the parameters.  Then, call getHash with the desired hash
variant (SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512) and output type
(HEX or B64).

In the example below, "This is a Test" and "SHA-512" were used
as the string to be hashed and variant respectively.  Also, the HMAC using TEXT
key "SecretKey" and hashing algorithm SHA-512 was calculated.

	var shaObj = new jsSHA("This is a Test", "TEXT");
	var hash = shaObj.getHash("SHA-512", "HEX");
	var hmac = shaObj.getHMAC("SecretKey", "TEXT", "SHA-512", "HEX");

The constructor takes an optional parameter, encoding, that specifies the
encoding used to encode TEXT-type inputs. Valid options are "UTF8" and "UTF16"
and it defaults to "UTF8"

Both getHash and getHMAC also take an optional has list parameter,
outputFormatOpts, that dictates some formatting options for the output.  By
default, `outputFormatOpts = {"outputUpper" : false, "b64Pad" : "="}`.  These
options are intelligently interpreted based upon the chosen output format.

Compiling
-------------------------
This library makes use of the Google Closure Compiler
(https://developers.google.com/closure/compiler) to both boost performance
and reduce filesizes.  To compile sha_dev.js into a customized output file, use
a command like the following:

	java -jar compiler.jar --define="SUPPORTED_ALGS=<FLAG>"
		--output_wrapper "(function() {%output%})();" --warning_level VERBOSE
		--compilation_level ADVANCED_OPTIMIZATIONS --js sha_dev.js --js_output_file sha.js
		
where <FLAG> is a bitwise OR of the following values:
  - 4 for SHA-384/SHA-512
  - 2 for SHA-224/256
  - 1 for SHA-1

Contact Info
-------------------------
The project's website is located at [http://caligatio.github.com/jsSHA/](http://caligatio.github.com/jsSHA/)
