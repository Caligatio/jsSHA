# jsSHA

A pure TypeScript/JavaScript streaming implementation of the complete Secure Hash Standard family (SHA-1, SHA-224,
SHA3-224, SHA-256, SHA3-256, SHA-384, SHA3-384, SHA-512, SHA3-512, SHAKE128, and SHAKE256) as well as HMAC.

![npm](https://img.shields.io/npm/v/jssha)
[![Build Status](https://travis-ci.org/Caligatio/jsSHA.svg?branch=master)](https://travis-ci.org/Caligatio/jsSHA)
[![Coverage Status](https://coveralls.io/repos/github/Caligatio/jsSHA/badge.svg?branch=master)](https://coveralls.io/github/Caligatio/jsSHA?branch=master)
![NPM](https://img.shields.io/npm/l/jssha)

## Usage

### Installation

#### Browser

Include the desired JavaScript file (sha.js, sha1.js, sha256.js, sha512.js, or sha3.js) in your header:

```html
<script type="text/javascript" src="/path/to/sha.js"></script>
<!-- You can also use the ECMAScript module (ESM) by using the following -->
<script type="module" src="/path/to/sha.mjs"></script>
```

#### Node.js

jsSHA is available through NPM and be installed by simply doing

```console
npm install jssha
```

To use the module, first require it using:

```javascript
const jsSHA = require("jssha");
// The limited variant files are also exported (sha1, sha256, sha512, and sha3)
const jsSHA1 = require("jssha/sha1");
// Alternatively, you can load it as a ESM
import jsSHA from "jssha";
```

### Hashing

Instantiate a new `jsSHA` object with the desired hash variant, input type, and options as parameters. The hash variant
can be one of SHA-1, SHA-224, SHA3-224, SHA-256, SHA3-256, SHA-384, SHA3-384, SHA-512, SHA3-512, SHAKE128, or SHAKE256.
The input type can be one of HEX, TEXT, B64, BYTES, ARRAYBUFFER, or UINT8ARRAY. You can then stream in input using the
`update` object function, calling it multiple times if needed. Finally, simply call `getHash` with the output type as a
parameter (B64, HEX, BYTES, ARRAYBUFFER, or UINT8ARRAY). Example to calculate the SHA-512 of "This is a test":

```javascript
const shaObj = new jsSHA("SHA-512", "TEXT", { encoding: "UTF8" });
shaObj.update("This is a ");
shaObj.update("test");
const hash = shaObj.getHash("HEX");
```

The constructor takes a hashmap as a optional third argument with defaults `{"encoding" : "UTF8", "numRounds" : 1}`.
`numRounds` controls the number of hashing iterations/rounds performed and `encoding` specifies the encoding used to
encode TEXT-type inputs. Valid options are "UTF8", "UTF16BE", and "UTF16LE", it defaults to "UTF8".

`getHash` also takes a hashmap as an optional second argument. By default the hashmap is
`{"outputUpper" : false, "b64Pad" : "="}`. These options are intelligently interpreted based upon the chosen output
format. **Important**: SHAKE128 and SHAKE256 require `shakeLen` to be included in the hashmap where `shakeLen` is the
desired output length of the SHAKE algorithm in a multiple of 8 bits.

### HMAC

Instantiate a new jsSHA object the same way as for hashing. Then set the HMAC key to be used by calling `setHMACKey`
with the key and its input type (this MUST be done before calling `update`). You can stream in the input using the
`update` object function just like hashing. Finally, get the HMAC by calling the `getHMAC` function with the output type
as its argument. Example to calculate the SHA-512 HMAC of the string "This is a test" with the key "abc":

```javascript
const shaObj = new jsSHA("SHA-512", "TEXT");
shaObj.setHMACKey("abc", "TEXT");
shaObj.update("This is a ");
shaObj.update("test");
const hmac = shaObj.getHMAC("HEX");
```

`setHMACKey` takes the same input types as the constructor and `getHMAC` takes the same inputs as `getHash` as described
above.

Note: You cannot calculate both the hash and HMAC using the same object.

## Files

**dist/sha.js**

The minified [UMD](https://github.com/umdjs/umd) version of the library with support for all hash variants. Its
accompanying source map can be found in sha.js.map and its TypeScript declarations in sha.d.ts.

**dist/sha.mjs**

The minified ESM version of the library with support for all hash variants. Its accompanying source map can be found in
sha.mjs.map and its TypeScript declarations in sha.d.ts.

**dist/sha1.js**

The minified UMD version of the library with support for only the SHA-1 hash variant.

**dist/sha256.js**

The minified UMD version of the library with support for only the SHA-224 and SHA-256 hash variants.

**dist/sha512.js**

The minified UMD version of the library with support for only the SHA-384 and SHA-512 hash variants.

**dist/sha3.js**

The minified UMD version of the library with support for only the SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, and
SHAKE256 hash variants.

## Contact Info

The project's website is located at [https://caligatio.github.com/jsSHA/](https://caligatio.github.com/jsSHA/)
