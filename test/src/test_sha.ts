import { describe, it } from "mocha";
import { assert } from "chai";
import jsSHA from "../../src/sha";
import { runHashTests } from "./common";

/* The below is less than ideal but rewire can't fiddle with imports so spying is hard */
[
  "SHA-1",
  "SHA-224",
  "SHA-256",
  "SHA-384",
  "SHA-512",
  "SHA3-224",
  "SHA3-256",
  "SHA3-384",
  "SHA3-512",
  "SHAKE128",
  "SHAKE256",
].forEach((variant) => {
  // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
  // @ts-ignore - Typescript doesn't understand the above array contains only valid values
  runHashTests(variant, jsSHA);
});

describe("Test jsSHA Constructor", () => {
  it("Invalid Variant", () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
    // @ts-ignore - Deliberate bad variant value
    assert.throws(() => new jsSHA("SHA-TEST", "HEX"), "Chosen SHA variant is not supported");
  });
});
