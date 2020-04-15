import { describe, it } from "mocha";
import { assert } from "chai";
import rewire from "rewire";
import sinon from "sinon";
import {
  FixedLengthOptionsEncodingType,
  FixedLengthOptionsNoEncodingType,
  FormatNoTextType,
} from "../../src/custom_types";
import { runHashTests } from "./common";

const sha256 = rewire("../../src/sha256"),
  newState224 = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4],
  newState256 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
  abcPostProcessed = [0x61626380, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000018],
  abcPacked = [0x61626300];

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
      0x23097d22,
      0x3405d822,
      0x8642a477 | 0,
      0xbda255b3 | 0,
      0x2aadbce4,
      0xbda0b3f7 | 0,
      0xe36c9da7 | 0,
      0xd2da082d | 0,
    ]);
  });

  it("SHA-256 With NIST Test Inputs", () => {
    assert.deepEqual(roundSHA256(abcPostProcessed, newState256.slice()), [
      0xba7816bf | 0,
      0x8f01cfea | 0,
      0x414140de,
      0x5dae2223,
      0xb00361a3 | 0,
      0x96177a9c | 0,
      0xb410ff61 | 0,
      0xf20015ad | 0,
    ]);
  });
});

describe("Test finalizeSHA256", () => {
  const array8Zeros = [0, 0, 0, 0, 0, 0, 0, 0];
  it("SHA-224 With NIST Test Inputs", () => {
    const roundStub = sinon.stub().returns(array8Zeros);
    sha256.__with__({ roundSHA256: roundStub })(() => {
      sha256.__get__("finalizeSHA256")(abcPacked, 24, 0, newState224.slice(), "SHA-224");
      assert.isTrue(roundStub.calledOnceWithExactly(abcPostProcessed, newState224.slice()));
    });
  });

  it("SHA-256 With NIST Test Inputs", () => {
    const roundStub = sinon.stub().returns(array8Zeros);
    sha256.__with__({ roundSHA256: roundStub })(() => {
      sha256.__get__("finalizeSHA256")(abcPacked, 24, 0, newState256.slice(), "SHA-256");
      assert.isTrue(roundStub.calledOnceWithExactly(abcPostProcessed, newState256.slice()));
    });
  });
});

describe("Test jsSHA(SHA-256)", () => {
  const jsSHA = sha256.__get__("jsSHA");
  class jsSHAATest extends jsSHA {
    constructor(variant: "SHA-224" | "SHA-256", inputFormat: "TEXT", options?: FixedLengthOptionsEncodingType);
    constructor(
      variant: "SHA-224" | "SHA-256",
      inputFormat: FormatNoTextType,
      options?: FixedLengthOptionsNoEncodingType
    );
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    constructor(variant: any, inputFormat: any, options?: any) {
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

  [
    { variant: "SHA-224", outputBinLen: 224 },
    { variant: "SHA-256", outputBinLen: 256 },
  ].forEach((test) => {
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
        newStateFuncSpy = sinon.spy();
      sha256.__with__({ roundSHA256: roundFuncSpy, finalizeSHA256: finalizeFuncSpy, getNewState256: newStateFuncSpy })(
        () => {
          // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
          // @ts-ignore
          const hash = new jsSHAATest(test.variant, "HEX");

          // Check #1
          assert.equal(hash.getter("bigEndianMod"), -1);
          assert.equal(hash.getter("variantBlockSize"), 512);
          assert.equal(hash.getter("outputBinLen"), test.outputBinLen);
          assert.isFalse(hash.getter("isVariableLen"));

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
        }
      );
    });
  });

  it("With Invalid Variant", () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
    // @ts-ignore - Deliberate bad variant value to test exceptions
    assert.throws(() => new jsSHA("SHA-TEST", "HEX"), "Chosen SHA variant is not supported");
  });

  it("With hmacKey Set at Instantiation", () => {
    const hash = new jsSHAATest("SHA-256", "HEX", { hmacKey: { value: "TEST", format: "TEXT" } });
    assert.isTrue(hash.getter("macKeySet"));
  });

  it("With hmacKey Set at Instantiation but then also setHMACKey", () => {
    const hash = new jsSHAATest("SHA-256", "HEX", { hmacKey: { value: "TEST", format: "TEXT" } });
    assert.throws(() => {
      hash.setHMACKey("TEST", "TEXT");
    }, "MAC key already set");
  });
});

runHashTests("SHA-224", sha256.__get__("jsSHA"));
runHashTests("SHA-256", sha256.__get__("jsSHA"));
