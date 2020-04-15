import { describe, it } from "mocha";
import { assert } from "chai";
import rewire from "rewire";
import sinon from "sinon";
import { runHashTests } from "./common";
import { Int_64 } from "../../src/primitives_64";
import {
  CSHAKEOptionsNoEncodingType,
  CSHAKEOptionsEncodingType,
  KMACOptionsNoEncodingType,
  KMACOptionsEncodingType,
  FixedLengthOptionsEncodingType,
  FixedLengthOptionsNoEncodingType,
  FormatNoTextType,
} from "../../src/custom_types";
import {
  NISTCSHAKERoundIn,
  CSHAKEWithFuncRoundIn,
  newState,
  NISTSHA3Round1In,
  NISTSHA3Round1Out,
  NISTSHA3Round2In,
  NISTSHA3Round2Out,
  SHAKE128Len2048Out,
  NISTKMACCustomizationRound1In,
  NISTKMACCustomizationRound2In,
} from "./test_sha3_consts";

const sha3 = rewire("../../src/sha3");

type VariantNoCSHAKEType = "SHA3-224" | "SHA3-256" | "SHA3-384" | "SHA3-512" | "SHAKE128" | "SHAKE256";

const getNewState = sha3.__get__("getNewState");

describe("Test left_encode", () => {
  const left_encode = sha3.__get__("left_encode");
  it("For 0-byte Value", () => {
    assert.deepEqual(left_encode(0), { value: [0x00000001], binLen: 16 });
  });
  it("For 1-byte Value", () => {
    assert.deepEqual(left_encode(0x11), { value: [0x000001101], binLen: 16 });
  });
  it("For 2-byte Value", () => {
    assert.deepEqual(left_encode(0x1122), { value: [0x000221102], binLen: 24 });
  });
  it("For 3-byte Value", () => {
    assert.deepEqual(left_encode(0x112233), { value: [0x33221103], binLen: 32 });
  });
  it("For 4-byte Value", () => {
    assert.deepEqual(left_encode(0x11223344), { value: [0x33221104, 0x00000044], binLen: 40 });
  });
  it("For 7-byte Value", () => {
    /* 4822678189205111 === 0x0011223344556677 */
    assert.deepEqual(left_encode(4822678189205111), { value: [0x33221107 | 0, 0x77665544 | 0], binLen: 64 });
  });
});

describe("Test right_encode", () => {
  const right_encode = sha3.__get__("right_encode");
  it("For 0-byte Value", () => {
    assert.deepEqual(right_encode(0), { value: [0x00000100], binLen: 16 });
  });
  it("For 1-byte Value", () => {
    assert.deepEqual(right_encode(0x11), { value: [0x000000111], binLen: 16 });
  });
  it("For 2-byte Value", () => {
    assert.deepEqual(right_encode(0x1122), { value: [0x00022211], binLen: 24 });
  });
  it("For 3-byte Value", () => {
    assert.deepEqual(right_encode(0x112233), { value: [0x03332211], binLen: 32 });
  });
  it("For 4-byte Value", () => {
    assert.deepEqual(right_encode(0x11223344), { value: [0x44332211, 0x00000004], binLen: 40 });
  });
  it("For 7-byte Value", () => {
    /* 4822678189205111 === 0x0011223344556677 */
    assert.deepEqual(right_encode(4822678189205111), { value: [0x44332211 | 0, 0x07776655], binLen: 64 });
  });
});

describe("Test encode_string", () => {
  let i, arr: number[];
  const encode_string = sha3.__get__("encode_string");

  it("For 0-bit Input", () => {
    assert.deepEqual(encode_string({ value: [], binLen: 0 }), { value: [0x00000001], binLen: 16 });
  });

  it("For 16-bit Input", () => {
    /* This checks values that can be encoded in a single int */
    assert.deepEqual(encode_string({ value: [0x1122], binLen: 16 }), { value: [0x11221001], binLen: 32 });
  });

  it("For 24-bit Input", () => {
    /* This checks values that can be encoded in 2 ints (and left_encode returns a 16-bit value) */
    assert.deepEqual(encode_string({ value: [0x112233], binLen: 24 }), { value: [0x22331801, 0x00000011], binLen: 40 });
  });

  it("For 256-bit Input", () => {
    /* This hits on the case that left_encode returns a 24-bit value */
    arr = [];
    const retVal = [0x41000102];
    for (i = 0; i < 8; i++) {
      arr.push(0x41414141);
    }
    for (i = 0; i < 7; i++) {
      retVal.push(0x41414141);
    }
    retVal.push(0x00414141);
    assert.deepEqual(encode_string({ value: arr, binLen: 256 }), { value: retVal, binLen: 280 });
  });

  it("For 65536-bit Input", () => {
    /* This hits on the case that left_encode returns a 32-bit value */
    arr = [];
    for (i = 0; i < 2048; i++) {
      arr.push(0x41414141);
    }
    assert.deepEqual(encode_string({ value: arr, binLen: 65536 }), { value: [0x00000103].concat(arr), binLen: 65568 });
  });

  it("For 16777216-bit Input", () => {
    /* This hits on the case that left_encode returns a 40-bit value */
    arr = [];
    for (i = 0; i < 524288; i++) {
      arr.push(0x41414141);
    }
    const retVal = encode_string({ value: arr, binLen: 16777216 });

    /* It's extremely time prohibitive to check all the middle bits so just check the interesting ends */
    assert.equal(retVal["value"][0], [0x00000104]);
    assert.equal(retVal["value"][1], [0x41414100]);
    assert.equal(retVal["value"].length, 524288 + 2);
    assert.equal(retVal["value"][retVal["value"].length - 1], [0x00000041]);
    assert.equal(retVal["binLen"], 16777256);
  });
});

describe("Test byte_pad", () => {
  const byte_pad = sha3.__get__("byte_pad");
  it("For 2-byte Value Padded to 4-bytes", () => {
    assert.deepEqual(byte_pad({ value: [0x00001122], binLen: 16 }, 4), [0x11220401]);
  });

  it("For 2-byte Value Padded to 8-bytes", () => {
    assert.deepEqual(byte_pad({ value: [0x00001122], binLen: 16 }, 8), [0x11220801, 0]);
  });
  it("For 4-byte Value Padded to 8-bytes", () => {
    assert.deepEqual(byte_pad({ value: [0x11223344], binLen: 32 }, 8), [0x33440801, 0x00001122]);
  });
  it("For 6-byte Value Padded to 8-bytes", () => {
    assert.deepEqual(byte_pad({ value: [0x44332211, 0x00006655], binLen: 48 }, 8), [0x22110801, 0x66554433]);
  });
});

describe("Test resolveCSHAKEOptions", () => {
  const resolveCSHAKEOptions = sha3.__get__("resolveCSHAKEOptions");
  it("With No Input", () => {
    assert.deepEqual(resolveCSHAKEOptions(), {
      funcName: { value: [], binLen: 0 },
      customization: { value: [], binLen: 0 },
    });
  });

  it("With customization Specified", () => {
    assert.deepEqual(resolveCSHAKEOptions({ customization: { value: "00112233", format: "HEX" } }), {
      funcName: { value: [], binLen: 0 },
      customization: { value: [0x33221100], binLen: 32 },
    });
  });

  it("With funcName Specified", () => {
    assert.deepEqual(resolveCSHAKEOptions({ funcName: { value: "00112233", format: "HEX" } }), {
      customization: { value: [], binLen: 0 },
      funcName: { value: [0x33221100], binLen: 32 },
    });
  });
});

describe("Test resolveKMACOptions", () => {
  const resolveKMACOptions = sha3.__get__("resolveKMACOptions");
  it("With No Input", () => {
    assert.throws(() => {
      resolveKMACOptions();
    }, "kmacKey must include a value and format");
  });

  it("With customization Specified", () => {
    assert.deepEqual(
      resolveKMACOptions({
        kmacKey: { value: "44556677", format: "HEX" },
        customization: { value: "00112233", format: "HEX" },
      }),
      {
        funcName: { value: [0x43414d4b], binLen: 32 },
        customization: { value: [0x33221100], binLen: 32 },
        kmacKey: { value: [0x77665544], binLen: 32 },
      }
    );
  });

  it("With funcName Specified", () => {
    assert.deepEqual(
      resolveKMACOptions({
        kmacKey: { value: "44556677", format: "HEX" },
        funcName: { value: "00112233", format: "HEX" },
      }),
      {
        funcName: { value: [0x43414d4b], binLen: 32 },
        customization: { value: [], binLen: 0 },
        kmacKey: { value: [0x77665544], binLen: 32 },
      }
    );
  });
});

describe("Test getNewState", () => {
  it("For All Variants", () => {
    assert.deepEqual(getNewState("SHA3-224"), newState);
  });
});

describe("Test cloneSHA3State", () => {
  const cloneSHA3State = sha3.__get__("cloneSHA3State");

  const state = [
    [new Int_64(0, 1), new Int_64(0, 2), new Int_64(0, 3), new Int_64(0, 4), new Int_64(0, 5)],
    [new Int_64(0, 6), new Int_64(0, 7), new Int_64(0, 8), new Int_64(0, 9), new Int_64(0, 0xa)],
    [new Int_64(0, 0xb), new Int_64(0, 0xc), new Int_64(0, 0xd), new Int_64(0, 0xb), new Int_64(0, 0xf)],
    [new Int_64(0, 0x10), new Int_64(0, 0x11), new Int_64(0, 0x12), new Int_64(0, 0x3), new Int_64(0, 0x14)],
    [new Int_64(0, 0x15), new Int_64(0, 0x16), new Int_64(0, 0x17), new Int_64(0, 0x18), new Int_64(0, 0x19)],
  ];

  it("For All Variants", () => {
    assert.notEqual(cloneSHA3State(state), state);
    assert.deepEqual(cloneSHA3State(state), state);
  });
});

describe("Test roundSHA3", () => {
  it("With NIST Test Inputs", () => {
    assert.deepEqual(sha3.__get__("roundSHA3")(NISTSHA3Round1In.slice(), getNewState()), NISTSHA3Round1Out);
  });
});

describe("Test finalizeSHA3", () => {
  it("With NIST Test Inputs", () => {
    const roundStub = sinon.stub().onCall(0).returns(NISTSHA3Round1Out).onCall(1).returns(NISTSHA3Round2Out);
    sha3.__with__({ roundSHA3: roundStub })(() => {
      assert.deepEqual(
        sha3.__get__("finalizeSHA3")(
          NISTSHA3Round1In.concat(NISTSHA3Round2In),
          1600,
          -1,
          getNewState(),
          1152,
          0x06,
          224
        ),
        [0x6a817693, 0x723f50ba, 0xebe76cf9, 0x5d09ac65, 0x4bbee3ee, 0xa1c2bbf9, 0xe0117ecb]
      );
    });
  });

  it("With outputLen Greater Than Blocksize", () => {
    // This is emulating SHAKE128 */
    assert.deepEqual(
      sha3.__get__("finalizeSHA3")(
        NISTSHA3Round1In.concat(NISTSHA3Round2In),
        1600,
        -1,
        getNewState(),
        1344,
        0x1f,
        2048
      ),
      SHAKE128Len2048Out
    );
  });
});

describe("Test jsSHA(SHA3)", () => {
  const jsSHA = sha3.__get__("jsSHA");
  class jsSHAATest extends jsSHA {
    constructor(variant: VariantNoCSHAKEType, inputFormat: "TEXT", options?: FixedLengthOptionsEncodingType);
    constructor(
      variant: VariantNoCSHAKEType,
      inputFormat: FormatNoTextType,
      options?: FixedLengthOptionsNoEncodingType
    );
    constructor(variant: "CSHAKE128" | "CSHAKE256", inputFormat: "TEXT", options?: CSHAKEOptionsEncodingType);
    constructor(
      variant: "CSHAKE128" | "CSHAKE256",
      inputFormat: FormatNoTextType,
      options?: CSHAKEOptionsNoEncodingType
    );
    constructor(variant: "KMAC128" | "KMAC256", inputFormat: "TEXT", options: KMACOptionsEncodingType);
    constructor(variant: "KMAC128" | "KMAC256", inputFormat: FormatNoTextType, options: KMACOptionsNoEncodingType);
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
    /*
     * Dirty hack function to expose the protected members of jsSHABase
     */
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    setter(propName: string, value: any): void {
      // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
      // @ts-ignore - Override "any" ban as this is only used in testing
      this[propName] = value;
    }
  }

  [
    {
      variant: "SHA3-224",
      outputBinLen: 224,
      variantBlockSize: 1152,
      delimiter: 0x06,
      HMACSupported: true,
      isVariableLen: false,
    },
    {
      variant: "SHA3-256",
      outputBinLen: 256,
      variantBlockSize: 1088,
      delimiter: 0x06,
      HMACSupported: true,
      isVariableLen: false,
    },
    {
      variant: "SHA3-384",
      outputBinLen: 384,
      variantBlockSize: 832,
      delimiter: 0x06,
      HMACSupported: true,
      isVariableLen: false,
    },
    {
      variant: "SHA3-512",
      outputBinLen: 512,
      variantBlockSize: 576,
      delimiter: 0x06,
      HMACSupported: true,
      isVariableLen: false,
    },
    {
      variant: "SHAKE128",
      outputBinLen: -1,
      variantBlockSize: 1344,
      delimiter: 0x1f,
      HMACSupported: false,
      isVariableLen: true,
    },
    {
      variant: "SHAKE256",
      outputBinLen: -1,
      variantBlockSize: 1088,
      delimiter: 0x1f,
      HMACSupported: false,
      isVariableLen: true,
    },
    {
      // Test whether empty customization + function-name "reverts" CSHAKE to SHAKE
      variant: "CSHAKE128",
      outputBinLen: -1,
      variantBlockSize: 1344,
      delimiter: 0x1f,
      isVariableLen: true,
      HMACSupported: false,
      customization: { value: "", format: "TEXT" },
    },
    {
      // Test whether empty customization + function-name "reverts" CSHAKE to SHAKE
      variant: "CSHAKE256",
      outputBinLen: -1,
      variantBlockSize: 1088,
      delimiter: 0x1f,
      isVariableLen: true,
      HMACSupported: false,
      customization: { value: "", format: "TEXT" },
    },
    {
      variant: "CSHAKE128",
      outputBinLen: -1,
      variantBlockSize: 1344,
      delimiter: 0x04,
      isVariableLen: true,
      HMACSupported: false,
      customization: { value: "a", format: "TEXT" },
    },
    {
      variant: "CSHAKE256",
      outputBinLen: -1,
      variantBlockSize: 1088,
      delimiter: 0x04,
      isVariableLen: true,
      HMACSupported: false,
      customization: { value: "a", format: "TEXT" },
    },
    {
      variant: "KMAC128",
      outputBinLen: -1,
      variantBlockSize: 1344,
      delimiter: 0x04,
      isVariableLen: true,
      HMACSupported: false,
      kmacKey: { value: "a", format: "TEXT" },
    },
    {
      variant: "KMAC256",
      outputBinLen: -1,
      variantBlockSize: 1088,
      delimiter: 0x04,
      isVariableLen: true,
      HMACSupported: false,
      kmacKey: { value: "a", format: "TEXT" },
    },
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
      sha3.__with__({ roundSHA3: roundFuncSpy, finalizeSHA3: finalizeFuncSpy, getNewState: newStateFuncSpy })(() => {
        // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
        // @ts-ignore
        const hash = new jsSHAATest(test.variant, "HEX", { customization: test.customization, kmacKey: test.kmacKey });

        // Check #1
        assert.equal(hash.getter("bigEndianMod"), 1);
        assert.equal(hash.getter("variantBlockSize"), test.variantBlockSize);
        assert.equal(hash.getter("outputBinLen"), test.outputBinLen);
        assert.equal(hash.getter("isVariableLen"), test.isVariableLen);
        assert.equal(hash.getter("HMACSupported"), test.HMACSupported);

        // Check #2
        const state = [[0xdeadbeef], [0xdeadbeef], [0xdeadbeef], [0xdeadbeef], [0xdeadbeef]];
        const clonedState = hash.getter("stateCloneFunc")(state);
        assert.notEqual(state, clonedState);
        assert.deepEqual(state, clonedState);

        // Check #3
        hash.getter("roundFunc")([0xdeadbeef], [[0xfacefeed]]);
        assert.isTrue(roundFuncSpy.lastCall.calledWithExactly([0xdeadbeef], [[0xfacefeed]]));

        //hash.getter("newStateFunc")(test.variant);
        assert.isTrue(newStateFuncSpy.lastCall.calledWithExactly(test.variant));

        hash.getter("finalizeFunc")([0xdeadbeef], 32, 0, [[0xfacefeed]], test.outputBinLen);
        assert.isTrue(
          finalizeFuncSpy.lastCall.calledWithExactly(
            [0xdeadbeef],
            32,
            0,
            [[0xfacefeed]],
            test.variantBlockSize,
            test.delimiter,
            test.outputBinLen
          )
        );
      });
    });
  });

  it("CSHAKE Without Options", () => {
    const hash = new jsSHAATest("CSHAKE128", "HEX");
    /* funcName and customization are both empty so nothing should be processed */
    assert.deepEqual(hash.getter("intermediateState"), newState);
    assert.equal(hash.getter("processedLen"), 0);
  });

  it("CSHAKE With Customization", () => {
    const roundSpy = sinon.spy();
    sha3.__with__({ roundSHA3: roundSpy })(() => {
      const hash = new jsSHAATest("CSHAKE128", "HEX", { customization: { value: "Email Signature", format: "TEXT" } });

      assert.isTrue(roundSpy.calledOnceWithExactly(NISTCSHAKERoundIn, newState.slice()));
      assert.equal(hash.getter("processedLen"), hash.getter("variantBlockSize"));
    });
  });

  it("CSHAKE With function-name", () => {
    const roundSpy = sinon.spy();
    sha3.__with__({ roundSHA3: roundSpy })(() => {
      const hash = new jsSHAATest("CSHAKE128", "HEX", { funcName: { value: "TEST", format: "TEXT" } });

      assert.isTrue(roundSpy.calledOnceWithExactly(CSHAKEWithFuncRoundIn, newState.slice()));
      assert.equal(hash.getter("processedLen"), hash.getter("variantBlockSize"));
    });
  });

  it("KMAC128 With Customization", () => {
    const roundSpy = sinon.spy();
    sha3.__with__({ roundSHA3: roundSpy })(() => {
      const hash = new jsSHAATest("KMAC128", "HEX", {
        customization: { value: "My Tagged Application", format: "TEXT" },
        kmacKey: { value: "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F", format: "HEX" },
      });

      assert.isTrue(roundSpy.getCall(0).calledWith(NISTKMACCustomizationRound1In));
      assert.isTrue(roundSpy.getCall(1).calledWith(NISTKMACCustomizationRound2In));
      assert.equal(hash.getter("processedLen"), 2 * hash.getter("variantBlockSize"));
    });
  });

  it("With Invalid Variant", () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
    // @ts-ignore - Deliberate bad variant value to test exceptions
    assert.throws(() => new jsSHA("SHA-TEST", "HEX"), "Chosen SHA variant is not supported");
  });

  it("CSHAKE With numRounds", () => {
    assert.throws(() => new jsSHA("CSHAKE128", "HEX", { numRounds: 2 }), "Cannot set numRounds for CSHAKE variants");
  });

  it("CSHAKE Without Customization Value", () => {
    assert.throws(
      () => new jsSHA("CSHAKE128", "HEX", { customization: { format: "TEXT" } }),
      "Customization must include a value and format"
    );
  });

  it("CSHAKE Without Customization Format", () => {
    assert.throws(
      () => new jsSHA("CSHAKE128", "HEX", { customization: { value: "abc" } }),
      "Customization must include a value and format"
    );
  });

  it("CSHAKE With funcName Missing format", () => {
    assert.throws(
      () =>
        new jsSHA("CSHAKE128", "HEX", { customization: { value: "abc", format: "TEXT" }, funcName: { value: "A" } }),
      "funcName must include a value and format"
    );
  });

  it("CSHAKE With funcName Missing Value", () => {
    assert.throws(
      () =>
        new jsSHA("CSHAKE128", "HEX", {
          customization: { value: "abc", format: "TEXT" },
          funcName: { format: "TEXT" },
        }),
      "funcName must include a value and format"
    );
  });

  it("KMAC128 With numRounds", () => {
    assert.throws(
      () => new jsSHA("KMAC128", "HEX", { numRounds: 2, kmacKey: { value: "TEST", format: "TEXT" } }),
      "Cannot set numRounds with MAC"
    );
  });

  it("KMAC128 Without kmacKey", () => {
    assert.throws(() => new jsSHA("KMAC128", "HEX"), "kmacKey must include a value and format");
  });

  it("KMAC128 With kmacKey Missing Value", () => {
    assert.throws(
      () => new jsSHA("KMAC128", "HEX", { kmacKey: { format: "HEX" } }),
      "kmacKey must include a value and format"
    );
  });

  it("KMAC128 With kmacKey Missing Format", () => {
    assert.throws(
      () => new jsSHA("KMAC128", "HEX", { kmacKey: { value: "AA" } }),
      "kmacKey must include a value and format"
    );
  });

  it("With hmacKey Set at Instantiation", () => {
    const hash = new jsSHAATest("SHA3-256", "HEX", { hmacKey: { value: "TEST", format: "TEXT" } });
    assert.isTrue(hash.getter("macKeySet"));
  });

  it("With hmacKey Set at Instantiation but then also setHMACKey", () => {
    const hash = new jsSHAATest("SHA3-256", "HEX", { hmacKey: { value: "TEST", format: "TEXT" } });
    assert.throws(() => {
      hash.setHMACKey("TEST", "TEXT");
    }, "MAC key already set");
  });
});

runHashTests("SHA3-224", sha3.__get__("jsSHA"));
runHashTests("SHA3-256", sha3.__get__("jsSHA"));
runHashTests("SHA3-384", sha3.__get__("jsSHA"));
runHashTests("SHA3-512", sha3.__get__("jsSHA"));
runHashTests("SHAKE128", sha3.__get__("jsSHA"));
runHashTests("SHAKE256", sha3.__get__("jsSHA"));
runHashTests("CSHAKE128", sha3.__get__("jsSHA"));
runHashTests("CSHAKE256", sha3.__get__("jsSHA"));
runHashTests("KMAC128", sha3.__get__("jsSHA"));
runHashTests("KMAC256", sha3.__get__("jsSHA"));
