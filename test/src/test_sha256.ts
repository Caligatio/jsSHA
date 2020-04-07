import { describe, it } from "mocha";
import { assert } from "chai";
import rewire from "rewire";
import sinon from "sinon";
import { runHashTests } from "./common";

const sha256 = rewire("../../src/sha256"),
  newState224 = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4],
  newState256 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
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
  abcPacked = [0x61626300]

describe("Test getNewState256", () => {
  const getNewState = sha256.__get__("getNewState256");

  it("For SHA-224", () => {
    assert.deepEqual(getNewState("SHA-224"), newState224);
  });

  it("For SHA-256", () => {
    assert.deepEqual(getNewState("SHA-256"), newState256);
  });
});

describe("Test roundSHA256", () => {
  const roundSHA256 = sha256.__get__("roundSHA256");

  it("SHA-224 With NIST Test Inputs", () => {
    assert.deepEqual(roundSHA256(abcPostProcessed, newState224.slice()), [
      0x23097D22,
      0x3405D822,
      0x8642A477 | 0,
      0xBDA255B3 | 0,
      0x2AADBCE4,
      0xBDA0B3F7 | 0,
      0xE36C9DA7 | 0,
      0xD2DA082D | 0
    ]);
  });

  it("SHA-256 With NIST Test Inputs", () => {
    assert.deepEqual(roundSHA256(abcPostProcessed, newState256.slice()), [
      0xBA7816BF | 0,
      0x8F01CFEA | 0,
      0x414140DE,
      0x5DAE2223,
      0xB00361A3 | 0,
      0x96177A9C | 0,
      0xB410FF61 | 0,
      0xF20015AD | 0
    ]);
  });
});

describe("Test finalizeSHA256", () => {
  it("SHA-224 With NIST Test Inputs", () => {
    const spy = sinon.spy(),
      finalizeSHA256 = sha256.__get__("finalizeSHA256"),
      revert = sha256.__set__("roundSHA256", spy);

    finalizeSHA256(abcPacked, 24, 0, newState224.slice());
    assert.isTrue(spy.calledOnceWithExactly(abcPostProcessed, newState224.slice()));
    revert();
  });

  it("SHA-256 With NIST Test Inputs", () => {
    const spy = sinon.spy(),
      finalizeSHA256 = sha256.__get__("finalizeSHA256"),
      revert = sha256.__set__("roundSHA256", spy);

    finalizeSHA256(abcPacked, 24, 0, newState256.slice());
    assert.isTrue(spy.calledOnceWithExactly(abcPostProcessed, newState256.slice()));
    revert();
  });
});

describe("Test jsSHA(SHA-256)", () => {
  const jsSHA = sha256.__get__("jsSHA");
  class jsSHAATest extends jsSHA {
    constructor(
      variant: "SHA-224" | "SHA-256",
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

  [{ variant: "SHA-224", outputBinLen: 224 }, { variant: "SHA-256", outputBinLen: 256 }].forEach((test) => {
    it(`${test.variant} State Initialization`, () => {
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
        roundRevert = sha256.__set__("roundSHA256", roundFuncSpy),
        finalizeRevert = sha256.__set__("finalizeSHA256", finalizeFuncSpy),
        newStateRevert = sha256.__set__("getNewState256", newStateFuncSpy),
        // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
        // @ts-ignore
        hash = new jsSHAATest(test.variant, "HEX");

      // Check #1
      assert.equal(hash.getter("bigEndianMod"), -1);
      assert.equal(hash.getter("variantBlockSize"), 512);
      assert.equal(hash.getter("outputBinLen"), test.outputBinLen);
      assert.isFalse(hash.getter("isSHAKE"));

      // Check #2
      const state = [0xdeadbeef];
      const clonedState = hash.getter("stateCloneFunc")(state);
      assert.notEqual(state, clonedState);
      assert.deepEqual(state, clonedState);

      // Check #3
      hash.getter("roundFunc")([0xdeadbeef], [0xfacefeed]);
      assert.isTrue(roundFuncSpy.lastCall.calledWithExactly([0xdeadbeef], [0xfacefeed]));

      hash.getter("newStateFunc")(test.variant);
      assert.isTrue(newStateFuncSpy.lastCall.calledWithExactly(test.variant));

      hash.getter("finalizeFunc")([0xdeadbeef], 32, 0, [0xfacefeed]);
      assert.isTrue(finalizeFuncSpy.lastCall.calledWithExactly([0xdeadbeef], 32, 0, [0xfacefeed], test.variant));

      roundRevert();
      finalizeRevert();
      newStateRevert();
    });
  });

  it("With Invalid Variant", () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
    // @ts-ignore - Deliberate bad variant value to test exceptions
    assert.throws(() => new jsSHA("SHA-TEST", "HEX"), "Chosen SHA variant is not supported");
  });
});

runHashTests("SHA-224", sha256.__get__("jsSHA"))
runHashTests("SHA-256", sha256.__get__("jsSHA"))
