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

const sha1 = rewire("../../src/sha1"),
  newState = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
  abcPostProcessed = [0x61626380, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000018],
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
    const spy = sinon.spy();
    sha1.__with__({ roundSHA1: spy })(() => {
      sha1.__get__("finalizeSHA1")(abcPacked, 24, 0, newState.slice());
      assert.isTrue(spy.calledOnceWithExactly(abcPostProcessed, newState.slice()));
    });
  });
});

describe("Test jsSHA(SHA-1)", () => {
  const jsSHA = sha1.__get__("jsSHA");

  class jsSHAATest extends jsSHA {
    constructor(variant: "SHA-1", inputFormat: "TEXT", options?: FixedLengthOptionsEncodingType);
    constructor(variant: "SHA-1", inputFormat: FormatNoTextType, options?: FixedLengthOptionsNoEncodingType);
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

  it("State Initialization", () => {
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
    sha1.__with__({ roundSHA1: roundFuncSpy, finalizeSHA1: finalizeFuncSpy, getNewState: newStateFuncSpy })(() => {
      const hash = new jsSHAATest("SHA-1", "HEX");

      // Check #1
      assert.equal(hash.getter("bigEndianMod"), -1);
      assert.equal(hash.getter("variantBlockSize"), 512);
      assert.equal(hash.getter("outputBinLen"), 160);
      assert.isFalse(hash.getter("isVariableLen"));

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
    });
  });

  it("With Invalid Variant", () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
    // @ts-ignore - Deliberate bad variant value to test exceptions
    assert.throws(() => new jsSHA("SHA-TEST", "HEX"), "Chosen SHA variant is not supported");
  });

  it("With hmacKey Set at Instantiation", () => {
    const hash = new jsSHAATest("SHA-1", "HEX", { hmacKey: { value: "TEST", format: "TEXT" } });
    assert.isTrue(hash.getter("macKeySet"));
  });

  it("With hmacKey Set at Instantiation but then also setHMACKey", () => {
    const hash = new jsSHAATest("SHA-1", "HEX", { hmacKey: { value: "TEST", format: "TEXT" } });
    assert.throws(() => {
      hash.setHMACKey("TEST", "TEXT");
    }, "MAC key already set");
  });
});

runHashTests("SHA-1", sha1.__get__("jsSHA"));
