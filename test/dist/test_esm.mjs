import jsSHA from "../../dist/sha.mjs";
import hashData from "../hash_data.js";
import mocha from "mocha";
import chai from "chai";

function testVariant(variant) {
  let success = true;

  try {
    mocha.describe(`Test ESM jsSHA(${variant}) Using NIST Tests`, () => {
      hashData[variant].forEach((test) => {
        test.outputs.forEach((output) => {
          const hashObj = new jsSHA(variant, test.input.type, { numRounds: test.input.rounds || 1 });
          mocha.it(test.name, () => {
            if (test.key) {
              hashObj.setHMACKey(test.key.value, test.key.type);
              hashObj.update(test.input.value);
              chai.assert.equal(hashObj.getHMAC(output.type), output.value);
            } else {
              hashObj.update(test.input.value);
              chai.assert.equal(hashObj.getHash(output.type, { shakeLen: output.shakeLen || 8 }), output.value);
            }
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
  ["SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE128", "SHAKE256"],
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
