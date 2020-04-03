import { describe, it } from "mocha";
import sinon from "sinon";
import { assert } from "chai";
import { getOutputOpts, jsSHABase } from "../src/common";
import { packedValue } from "../src/converters";

describe("Test getOutputOpts", () => {
  it("Empty Input", () => {
    assert.deepEqual(getOutputOpts(), { outputUpper: false, b64Pad: "=", shakeLen: -1 });
  });

  it("b64Pad Specified", () => {
    assert.deepEqual(getOutputOpts({ b64Pad: "#" }), { outputUpper: false, b64Pad: "#", shakeLen: -1 });
  });

  it("shakeLen Specified", () => {
    assert.deepEqual(getOutputOpts({ shakeLen: 8 }), { outputUpper: false, b64Pad: "=", shakeLen: 8 });
  });

  it("Invalid shakeLen", () => {
    assert.throws(() => {
      getOutputOpts({ shakeLen: 1 });
    }, "shakeLen must be a multiple of 8");
  });

  it("Invalid b64Pad", () => {
    assert.throws(() => {
      // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
      // @ts-ignore - Deliberate bad b64Pad value to test exceptions
      getOutputOpts({ b64Pad: 1 });
    }, "Invalid b64Pad formatting option");
  });

  it("Invalid outputUpper", () => {
    assert.throws(() => {
      // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
      // @ts-ignore - Deliberate bad outputUpper value to test exceptions
      getOutputOpts({ outputUpper: 1 });
    }, "Invalid outputUpper formatting option");
  });
});

describe("Test jsSHABase", () => {
  const stubbedStrConverter = sinon.stub(),
    stubbedRound = sinon.stub(),
    stubbedNewState = sinon.stub(),
    stubbedFinalize = sinon.stub(),
    stubbedStateClone = sinon.stub();

  class jsSHAATest extends jsSHABase<number[], "SHA-TEST"> {
    intermediateState: number[];
    variantBlockSize: number;
    bigEndianMod: -1 | 1;
    outputBinLen: number;
    isSHAKE: boolean;

    /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
    converterFunc: (input: any, existingBin: number[], existingBinLen: number) => packedValue;
    roundFunc: (block: number[], H: number[]) => number[];
    finalizeFunc: (remainder: number[], remainderBinLen: number, processedBinLen: number, H: number[]) => number[];
    stateCloneFunc: (state: number[]) => number[];
    newStateFunc: (variant: "SHA-TEST") => number[];

    constructor(
      variant: "SHA-TEST",
      inputFormat: "HEX" | "TEXT" | "B64" | "BYTES" | "ARRAYBUFFER" | "UINT8ARRAY",
      options?: { encoding?: "UTF8" | "UTF16BE" | "UTF16LE"; numRounds?: number }
    ) {
      super(variant, inputFormat, options);

      this.bigEndianMod = -1;
      this.converterFunc = stubbedStrConverter;
      this.roundFunc = stubbedRound;
      this.stateCloneFunc = stubbedStateClone;
      this.newStateFunc = (stubbedNewState as unknown) as (variant: "SHA-TEST") => number[];
      this.finalizeFunc = stubbedFinalize;

      this.intermediateState = [0];
      this.variantBlockSize = 64;
      this.outputBinLen = 64;
      this.isSHAKE = false;
    }

    /*
     * Dirty hack function to expose the protected members of jsSHABase
     */
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    propertySpy(propName: string): any {
      // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
      // @ts-ignore
      return this[propName];
    }
  }

  it("Test Constructor with Empty Options", () => {
    const stubbedJsSHA = new jsSHAATest("SHA-TEST", "HEX");

    assert.equal(stubbedJsSHA.propertySpy("inputFormat"), "HEX");
    assert.equal(stubbedJsSHA.propertySpy("utfType"), "UTF8");
    assert.equal(stubbedJsSHA.propertySpy("shaVariant"), "SHA-TEST");
    assert.equal(stubbedJsSHA.propertySpy("numRounds"), 1);
    assert.equal(stubbedJsSHA.propertySpy("remainderLen"), 0);
    assert.equal(stubbedJsSHA.propertySpy("processedLen"), 0);
    assert.isFalse(stubbedJsSHA.propertySpy("updateCalled"));
    assert.isFalse(stubbedJsSHA.propertySpy("hmacKeySet"));
    assert.deepEqual(stubbedJsSHA.propertySpy("inputOptions"), {});
    assert.deepEqual(stubbedJsSHA.propertySpy("remainder"), []);
    assert.deepEqual(stubbedJsSHA.propertySpy("keyWithIPad"), []);
    assert.deepEqual(stubbedJsSHA.propertySpy("keyWithOPad"), []);
  });

  it("Test Constructor with Bad numRounds", () => {
    assert.throws(() => {
      new jsSHAATest("SHA-TEST", "HEX", { numRounds: 1.2 });
    }, "numRounds must a integer >= 1");

    assert.throws(() => {
      new jsSHAATest("SHA-TEST", "HEX", { numRounds: -1 });
    }, "numRounds must a integer >= 1");
  });
});
