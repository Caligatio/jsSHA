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

      this.intermediateState = [0, 0];
      this.variantBlockSize = 64;
      this.outputBinLen = 64;
      this.isSHAKE = false;
    }

    /*
     * Dirty hack function to expose the protected members of jsSHABase
     */
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    getter(propName: string): any {
      // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
      // @ts-ignore
      return this[propName];
    }

    /*
     * Dirty hack function to expose the protected members of jsSHABase
     */
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    setter(propName: string, value: any): void {
      // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
      // @ts-ignore
      this[propName] = value;
    }
  }

  it("Test Constructor with Empty Options", () => {
    const stubbedJsSHA = new jsSHAATest("SHA-TEST", "HEX");

    assert.equal(stubbedJsSHA.getter("inputFormat"), "HEX");
    assert.equal(stubbedJsSHA.getter("utfType"), "UTF8");
    assert.equal(stubbedJsSHA.getter("shaVariant"), "SHA-TEST");
    assert.equal(stubbedJsSHA.getter("numRounds"), 1);
    assert.equal(stubbedJsSHA.getter("remainderLen"), 0);
    assert.equal(stubbedJsSHA.getter("processedLen"), 0);
    assert.isFalse(stubbedJsSHA.getter("updateCalled"));
    assert.isFalse(stubbedJsSHA.getter("hmacKeySet"));
    assert.deepEqual(stubbedJsSHA.getter("inputOptions"), {});
    assert.deepEqual(stubbedJsSHA.getter("remainder"), []);
    assert.deepEqual(stubbedJsSHA.getter("keyWithIPad"), []);
    assert.deepEqual(stubbedJsSHA.getter("keyWithOPad"), []);
  });

  it("Test Constructor with Bad numRounds", () => {
    assert.throws(() => {
      new jsSHAATest("SHA-TEST", "HEX", { numRounds: 1.2 });
    }, "numRounds must a integer >= 1");

    assert.throws(() => {
      new jsSHAATest("SHA-TEST", "HEX", { numRounds: -1 });
    }, "numRounds must a integer >= 1");
  });

  it("Test update", () => {
    /*
     * This is rather difficult to test so we want to check a few basic things:
     *   1. It passed the input to the string conversion function correctly
     *   2. It did *not* call the round function when the input was smaller than the block size
     *   3. Intermediate state was untouched but remainder variables are updated
     *   4. It *did* call the round function when the input was greater than or equal to than the block size
     *   5. Intermediate state and associated variables are set correctly
     */
    const stubbedJsSHA = new jsSHAATest("SHA-TEST", "HEX"),
      inputStr = "ABCD";
    sinon.reset();

    stubbedStrConverter
      .onFirstCall()
      .returns({ value: [0x00112233], binLen: 32 })
      .onSecondCall()
      .returns({ value: [0x00112233, 0x00112233], binLen: 64 });
    stubbedRound.returns([0x00112233, 0xaabbccdd]);

    stubbedJsSHA.update(inputStr);
    // Check #1
    assert.isTrue(stubbedStrConverter.calledOnceWith(inputStr, [], 0));
    // Check #2
    assert.isFalse(stubbedRound.called);
    // Check #3
    assert.deepEqual(stubbedJsSHA.getter("intermediateState"), [0, 0]);
    assert.deepEqual(stubbedJsSHA.getter("remainder"), [0x00112233]);
    assert.equal(stubbedJsSHA.getter("remainderLen"), 32);
    assert.equal(stubbedJsSHA.getter("processedLen"), 0);
    assert.isTrue(stubbedJsSHA.getter("updateCalled"));

    stubbedJsSHA.update(inputStr);
    // Check #1 again to make sure state is being passed correctly
    assert.equal(stubbedStrConverter.callCount, 2);
    assert.isTrue(stubbedStrConverter.getCall(1).calledWithExactly(inputStr, [0x00112233], 32));
    // Check #4
    assert.isTrue(stubbedRound.calledOnceWith([0x00112233, 0x00112233], [0, 0]));

    // Check #5
    assert.deepEqual(stubbedJsSHA.getter("intermediateState"), [0x00112233, 0xaabbccdd]);
    assert.deepEqual(stubbedJsSHA.getter("remainder"), []);
    assert.equal(stubbedJsSHA.getter("remainderLen"), 0);
    assert.equal(stubbedJsSHA.getter("processedLen"), 64);
  });

  it("Test getHash Without Needed shakeLen ", () => {
    const stubbedJsSHA = new jsSHAATest("SHA-TEST", "HEX");

    stubbedJsSHA.setter("isSHAKE", true);
    assert.throws(() => {
      stubbedJsSHA.getHash("HEX", {});
    }, "shakeLen must be specified in options");
  });

  it("Test getHash After setHMACKey Called", () => {
    const stubbedJsSHA = new jsSHAATest("SHA-TEST", "HEX");
    sinon.reset();

    // Bare minimum stubs for function not to throw exceptions
    stubbedStrConverter.returns({ value: [0x00112233], binLen: 32 });
    stubbedNewState.returns({ value: [0x00112233], binLen: 32 });
    stubbedFinalize.returns([0x00112233, 0xaabbccdd]);

    stubbedJsSHA.setHMACKey("ABCD", "HEX");

    assert.throws(() => {
      stubbedJsSHA.getHash("HEX");
    }, "Cannot call getHash after setting HMAC key");
  });

  it("Test getHash", () => {
    /*
     * Check a few basic things:
     *   1. The output of getHash should equal the first outputBinLen bits of the output of finalizeFunc
     *   2. intermediateState and remainder should not be changed by calling getHash
     *   3. finalize should be called once with the correct inputs
     */
    const stubbedJsSHA = new jsSHAATest("SHA-TEST", "HEX");
    sinon.reset();
    stubbedFinalize.returns([0x00112233, 0xaabbccdd]);
    stubbedStateClone.returns([0xdeadc0de, 0xfacefeed]);

    stubbedJsSHA.setter("intermediateState", [0xdeadbeef]);
    const intermediateState = stubbedJsSHA.getter("intermediateState");
    stubbedJsSHA.setter("remainder", [0xbaddcafe]);
    const remainder = stubbedJsSHA.getter("remainder");
    stubbedJsSHA.setter("remainderLen", 32);
    stubbedJsSHA.setter("processedLen", 64);

    // Check #1
    assert.equal(stubbedJsSHA.getHash("HEX"), "00112233aabbccdd");

    // Check #2, note deliberate use of equal vs deepEqual
    assert.equal(intermediateState, stubbedJsSHA.getter("intermediateState"));
    assert.equal(remainder, stubbedJsSHA.getter("remainder"));

    // Check #3
    assert.isTrue(stubbedFinalize.calledOnceWith([0xbaddcafe], 32, 64, [0xdeadc0de, 0xfacefeed], 64));
  });

  it("Test getHash for SHAKE", () => {
    /*
     * Check a few basic things:
     *   1. The output of getHash should equal the first shakeLen bits of the output of finalizeFunc
     *   2. finalize should be called once with the correct inputs
     */
    const stubbedJsSHA = new jsSHAATest("SHA-TEST", "HEX");
    stubbedJsSHA.setter("isSHAKE", true);
    sinon.reset();
    stubbedFinalize.returns([0x00112233, 0xaabbccdd]);
    stubbedStateClone.returns([0xdeadc0de, 0xfacefeed]);

    stubbedJsSHA.setter("intermediateState", [0xdeadbeef]);
    stubbedJsSHA.setter("remainder", [0xbaddcafe]);
    stubbedJsSHA.setter("remainderLen", 32);
    stubbedJsSHA.setter("processedLen", 64);

    // Check #1
    assert.equal(stubbedJsSHA.getHash("HEX", { shakeLen: 32 }), "00112233");

    // Check #2
    assert.isTrue(stubbedFinalize.calledOnceWith([0xbaddcafe], 32, 64, [0xdeadc0de, 0xfacefeed], 32));
  });

  it("Test getHash for numRounds=3", () => {
    /*
     * Check a few basic things:
     *   1. The output of getHash should equal the output of last finalizeFunc call
     *   2. finalizeFunc should be called numRound times
     */
    const stubbedJsSHA = new jsSHAATest("SHA-TEST", "HEX", { numRounds: 3 });
    sinon.reset();
    stubbedFinalize.returns([0x00112233, 0xaabbccdd]).onCall(2).returns([0xdeadc0de, 0xfacefeed]);

    // Check #1
    assert.equal(stubbedJsSHA.getHash("HEX"), "deadc0defacefeed");

    // Check #2
    assert.equal(stubbedFinalize.callCount, 3);
  });

  it("Test getHash for SHAKE numRounds=3", () => {
    /*
     * Check a few basic things:
     *   1. The output of getHash should equal the output of last finalizeFunc call
     *   2. finalizeFunc should be called numRound times
     *   3. The last numRound-1 calls of finalizeFunc should have the last 32-shakeLen bits 0ed out
     */
    const stubbedJsSHA = new jsSHAATest("SHA-TEST", "HEX", { numRounds: 3 });
    stubbedJsSHA.setter("isSHAKE", true);
    sinon.reset();
    stubbedFinalize.returns([0x00112233, 0xaabbccdd]).onCall(2).returns([0xdeadc0de, 0xfacefeed]);

    // Check #1
    assert.equal(stubbedJsSHA.getHash("HEX", { shakeLen: 24 }), "deadc0");

    // Check #2
    assert.equal(stubbedFinalize.callCount, 3);

    // Check #3
    stubbedFinalize.getCall(1).calledWith([0x00112233, 0x00bbccdd], 24);
    stubbedFinalize.getCall(2).calledWith([0x00112233, 0x00bbccdd], 24);
  });
});
