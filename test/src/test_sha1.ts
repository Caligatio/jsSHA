import { describe, it } from "mocha";
import { assert } from "chai";
import rewire from "rewire";
import sinon from "sinon";
import hashData from "../hash_data.js";

const sha1 = rewire("../../src/sha1"),
  newState = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
  abcPostProcessed = [
    0x61626380,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000018,
  ],
  abcPacked = [0x61626300];

describe("Test getNewState", () => {
  const getNewState = sha1.__get__("getNewState");

  it("With No Inputs", () => {
    assert.deepEqual(getNewState(), newState);
  });
});

describe("Test roundSHA1", () => {
  const roundSHA1 = sha1.__get__("roundSHA1");

  it("With NIST Test Inputs", () => {
    assert.deepEqual(roundSHA1(abcPostProcessed, newState.slice()), [
      0xa9993e36 | 0,
      0x4706816a,
      0xba3e2571 | 0,
      0x7850c26c,
      0x9cd0d89d | 0,
    ]);
  });
});

describe("Test finalizeSHA1", () => {
  it("With NIST Test Inputs", () => {
    const spy = sinon.spy(),
      finalizeSHA1 = sha1.__get__("finalizeSHA1"),
      revert = sha1.__set__("roundSHA1", spy);

    finalizeSHA1(abcPacked, 24, 0, newState.slice());
    assert.isTrue(spy.calledOnceWithExactly(abcPostProcessed, newState.slice()));
    revert();
  });
});

describe("Test jsSHA(1)", () => {
  const jsSHA = sha1.__get__("jsSHA");

  class jsSHAATest extends jsSHA {
    constructor(
      variant: "SHA-1",
      inputFormat: "HEX" | "TEXT" | "B64" | "BYTES" | "ARRAYBUFFER" | "UINT8ARRAY",
      options?: { encoding?: "UTF8" | "UTF16BE" | "UTF16LE"; numRounds?: number }
    ) {
      super(variant, inputFormat, options);
    }

    /*
     * Dirty hack function to expose the protected members of jsSHABase
     */
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    getter(propName: string): any {
      // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
      // @ts-ignore - Override "any" ban as this is only used in testing
      return this[propName];
    }
  }

  it("With NIST Test Inputs", () => {
    /*
     * Check a few basic things:
     *   1. All of the variant parameters are correct
     *   2. Calling stateClone function returns a *copy* of the state
     *   3. Calling roundFunc, newStateFunc, and finalizeFunc call the expected functions
     */
    sinon.reset();
    const roundFuncSpy = sinon.spy(),
      finalizeFuncSpy = sinon.spy(),
      newStateFuncSpy = sinon.spy(),
      roundRevert = sha1.__set__("roundSHA1", roundFuncSpy),
      finalizeRevert = sha1.__set__("finalizeSHA1", finalizeFuncSpy),
      newStateRevert = sha1.__set__("getNewState", newStateFuncSpy),
      hash = new jsSHAATest("SHA-1", "HEX");

    // Check #1
    assert.equal(hash.getter("bigEndianMod"), -1);
    assert.equal(hash.getter("variantBlockSize"), 512);
    assert.equal(hash.getter("outputBinLen"), 160);
    assert.isFalse(hash.getter("isSHAKE"));

    // Check #2
    const state = [0xdeadbeef];
    const clonedState = hash.getter("stateCloneFunc")(state);
    assert.notEqual(state, clonedState);
    assert.deepEqual(state, clonedState);

    // Check #3
    hash.getter("roundFunc")([0xdeadbeef], [0xfacefeed]);
    assert.isTrue(roundFuncSpy.lastCall.calledWithExactly([0xdeadbeef], [0xfacefeed]));

    hash.getter("newStateFunc")("SHA-1");
    assert.isTrue(newStateFuncSpy.lastCall.calledWithExactly("SHA-1"));

    hash.getter("finalizeFunc")([0xdeadbeef], 32, 0, [0xfacefeed]);
    assert.isTrue(finalizeFuncSpy.lastCall.calledWithExactly([0xdeadbeef], 32, 0, [0xfacefeed]));

    roundRevert();
    finalizeRevert();
    newStateRevert();
  });

  it("With Invalid Variant", () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
    // @ts-ignore - Deliberate bad variant value to test exceptions
    assert.throws(() => new jsSHA("SHA-TEST", "HEX"), "Chosen SHA variant is not supported");
  });
});

describe("Test jsSHA(1) Using NIST Tests", () => {
  const jsSHA = sha1.__get__("jsSHA");

  describe(`Test jsSHA(SHA-1) Using NIST Tests`, () => {
    hashData["SHA-1"].forEach((test) => {
      test.outputs.forEach((output) => {
        const hashObj = new jsSHA("SHA-1", test.input.type, { numRounds: test.input.rounds || 1 });
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
});
