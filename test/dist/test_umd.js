/* globals describe, it, assert, hashData, jsSHA, module */

/* The below if block allows this to work with preloaded globals (karma testing) and in node */
if (typeof exports === "object" && typeof module !== "undefined") {
  var chai = require("chai");
  var jsSHA = require("../../dist/sha.js");
  var hashData = require("../hash_data.js");

  var assert = chai.assert;
}

function testVariant(variant) {
  let success = true;

  try {
    describe(`Test UMD jsSHA(${variant}) Using NIST Tests`, () => {
      hashData[variant].forEach((test) => {
        test.outputs.forEach((output) => {
          // This constructor needs to be outside of the "it" otherwise the variant support exception will fail the test
          if (test.hmacKey) {
            const hashObj = new jsSHA(variant, test.input.format);
            it(test.name + " - Old Style", () => {
              hashObj.setHMACKey(test.hmacKey.value, test.hmacKey.format);
              hashObj.update(test.input.value);
              assert.equal(hashObj.getHMAC(output.format), output.value);
            });
          }
          const hashObj = new jsSHA(variant, test.input.format, {
            numRounds: test.input.rounds || 1,
            customization: test.customization,
            kmacKey: test.kmacKey,
            hmacKey: test.hmacKey,
          });
          it(test.name, () => {
            hashObj.update(test.input.value);
            assert.equal(hashObj.getHash(output.format, { outputLen: output.outputLen || 8 }), output.value);
          });
        });
      });
    });
  } catch (e) {
    if (e.message !== "Chosen SHA variant is not supported") {
      throw e;
    }
    success = false;
  }

  return success;
}

[
  ["SHA-1"],
  ["SHA-224", "SHA-256"],
  ["SHA-384", "SHA-512"],
  [
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "SHAKE128",
    "SHAKE256",
    "CSHAKE128",
    "CSHAKE256",
    "KMAC128",
    "KMAC256",
  ],
].forEach((shaFamily) => {
  let successes = 0;
  shaFamily.forEach((shaVariant) => {
    successes += testVariant(shaVariant) === true ? 1 : 0;
  });

  /* This should never happen but this catches the edge case of a jsSHA file having incomplete support for something
   * it is supposed to do.  For example, SHA-1 will be broken on all of SHA-224/256 (which is fine) but it would be a
   * problem if SHA-224 was supported but not SHA-256
   */
  if (successes !== 0 && successes !== shaFamily.length) {
    throw new Error("SHA family has incomplete variant support");
  }
});
