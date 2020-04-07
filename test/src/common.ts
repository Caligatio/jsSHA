import { describe, it } from "mocha";
import { assert } from "chai";
import hashData from "../hash_data.js";

export function runHashTests(
  variant:
    | "SHA-1"
    | "SHA-224"
    | "SHA-256"
    | "SHA-384"
    | "SHA-512"
    | "SHA3-224"
    | "SHA3-256"
    | "SHA3-384"
    | "SHA3-512"
    | "SHAKE128"
    | "SHAKE256",
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  jsSHA: any
): void {
  describe(`Test jsSHA(${variant}) Using NIST Tests`, () => {
    hashData[variant].forEach((test) => {
      test.outputs.forEach((output) => {
        const hashObj = new jsSHA(variant, test.input.type, { numRounds: test.input.rounds || 1 });
        it(test.name, () => {
          if (test.key) {
            hashObj.setHMACKey(test.key.value, test.key.type);
            hashObj.update(test.input.value);
            assert.equal(hashObj.getHMAC(output.type), output.value);
          } else {
            hashObj.update(test.input.value);
            assert.equal(hashObj.getHash(output.type, { shakeLen: output.shakeLen || 8 }), output.value);
          }
        });
      });
    });
  });
}
