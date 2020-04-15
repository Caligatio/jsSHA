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
    | "SHAKE256"
    | "CSHAKE128"
    | "CSHAKE256"
    | "KMAC128"
    | "KMAC256",
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  jsSHA: any
): void {
  describe(`Test jsSHA(${variant}) Using NIST Tests`, () => {
    hashData[variant].forEach((test) => {
      test.outputs.forEach((output) => {
        if (test.hmacKey) {
          it(test.name + " - Old Style", () => {
            const hashObj = new jsSHA(variant, test.input.format);
            // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
            // @ts-ignore
            hashObj.setHMACKey(test.hmacKey.value, test.hmacKey.format);
            hashObj.update(test.input.value);
            assert.equal(hashObj.getHMAC(output.format), output.value);
          });
        }
        it(test.name, () => {
          const hashObj = new jsSHA(variant, test.input.format, {
            numRounds: test.input.rounds || 1,
            customization: test.customization,
            kmacKey: test.kmacKey,
            hmacKey: test.hmacKey,
          });
          hashObj.update(test.input.value);
          assert.equal(hashObj.getHash(output.format, { outputLen: output.outputLen || 8 }), output.value);
        });
      });
    });
  });
}
