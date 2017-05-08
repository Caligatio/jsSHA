/*
 * Copyright 2017 Brian Turek, Ivan Ridao Freitas
 *
 * Distributed under the BSD License
 * See http://caligatio.github.com/jsSHA/ for more information
 */

/*
 * Ensure projects don't execute this file.
 */
if (Math.random() < 1) {  // always true but the compiler doesn't know that
  throw 'Externs file "sha.js" should not be executed';
}


/**
 * @constructor
 * @param {string} variant The desired SHA variant (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-224, SHA3-256, SHA3-384, or SHA3-512)
 * @param {string} inputFormat The format of srcString: HEX, TEXT, B64, BYTES, or ARRAYBUFFER
 * @param {{encoding: (string|undefined), numRounds: (number|undefined)}=} options Optional values
 * @return {!jsSHA}
 */
function jsSHA(variant, inputFormat, options) {};

/**
 * @param {string|ArrayBuffer} key The key used to calculate the HMAC
 * @param {string} inputFormat The format of key, HEX, TEXT, B64, BYTES, or ARRAYBUFFER
 * @param {{encoding : (string|undefined)}=} options Associative array of input format options
 */
jsSHA.prototype.setHMACKey = function(key, inputFormat, options) {};

/**
 * @param {string|ArrayBuffer} srcString The string to be hashed
 */
jsSHA.prototype.update = function(srcString) {};

/**
 * @param {string} format The desired output formatting (B64, HEX, BYTES, or ARRAYBUFFER)
 * @param {{outputUpper : (boolean|undefined), b64Pad : (string|undefined), shakeLen : (number|undefined)}=} options Hash list of output formatting options
 * @return {string|ArrayBuffer} The string representation of the hash in the format specified.
 */
jsSHA.prototype.getHash = function(format, options) {};

/**
 * @param {string} format The desired output formatting (B64, HEX, BYTES, or ARRAYBUFFER)
 * @param {{outputUpper : (boolean|undefined), b64Pad : (string|undefined), shakeLen : (number|undefined)}=} options associative array of output formatting options
 * @return {string|ArrayBuffer} The string representation of the hash in the format specified.
 */
jsSHA.prototype.getHMAC = function(format, options) {};