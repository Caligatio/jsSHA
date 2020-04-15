import { describe, it } from "mocha";
import rewire from "rewire";
import sinon from "sinon";
import { assert } from "chai";
import { packedValue } from "../../src/custom_types";

const converters = rewire("../../src/converters");

function newArrayBuffer(bytes: number[]): ArrayBuffer {
  const ab = new ArrayBuffer(bytes.length),
    ua = new Uint8Array(ab);
  for (let i = 0; i < ua.length; i++) {
    ua[i] = bytes[i];
  }
  return ab;
}

const toPackedTests = [
  {
    name: "4-byte Input",
    inputs: {
      hex: "41424344",
      b64: "QUJDRA==",
      arrayBuffer: newArrayBuffer([0x41, 0x42, 0x43, 0x44]),
      uint8Array: Uint8Array.from([0x41, 0x42, 0x43, 0x44]),
      existing: [0x45000000],
      existingMod: [0x00000045],
      lengthExisting: 8,
    },
    outputs: {
      original: [0x41424344],
      existing: [0x45414243, 0x44000000],
      originalMod: [0x44434241],
      existingMod: [0x43424145, 0x00000044],
      length: 32,
    },
  },
];

function toPackedTestsBuilder(
  funcToTest: (
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    input: any,
    existingBin: number[] | undefined,
    existingBinLen: number | undefined,
    bigEndianMod: -1 | 1
  ) => packedValue,
  inputType: "hex" | "b64" | "arrayBuffer" | "uint8Array"
): void {
  toPackedTests.forEach((test) => {
    it(`${test.name} - No Existing Input`, () => {
      assert.deepEqual(funcToTest(test.inputs[inputType], undefined, undefined, -1), {
        value: test.outputs.original,
        binLen: test.outputs.length,
      });
    });
    it(`${test.name} - Existing Input`, () => {
      assert.deepEqual(
        funcToTest(test.inputs[inputType], test.inputs.existing.slice(), test.inputs.lengthExisting, -1),
        {
          value: test.outputs.existing,
          binLen: test.outputs.length + test.inputs.lengthExisting,
        }
      );
    });
    it(`${test.name} - No Existing Input with Endian Modifier`, () => {
      assert.deepEqual(funcToTest(test.inputs[inputType], undefined, undefined, 1), {
        value: test.outputs.originalMod,
        binLen: test.outputs.length,
      });
    });
    it(`${test.name} - Existing Input with Endian Modifier`, () => {
      assert.deepEqual(
        funcToTest(test.inputs[inputType], test.inputs.existingMod.slice(), test.inputs.lengthExisting, 1),
        {
          value: test.outputs.existingMod,
          binLen: test.outputs.length + test.inputs.lengthExisting,
        }
      );
    });
  });
}

describe("Test hex2packed", () => {
  const hex2packed = converters.__get__("hex2packed");

  // Basic I/O tests
  toPackedTestsBuilder(hex2packed, "hex");

  // Input Validation Tests
  it("Invalid Length Exception", () => {
    assert.throws(() => {
      hex2packed("F", undefined, undefined, -1);
    }, "String of HEX type must be in byte increments");
  });
  it("Invalid Character Exception", () => {
    assert.throws(() => {
      hex2packed("GG", [], 0 - 1);
    }, "String of HEX type contains invalid characters");
  });
});

describe("Test b642packed", () => {
  const b642packed = converters.__get__("b642packed");

  // Basic I/O tests
  toPackedTestsBuilder(b642packed, "b64");

  // Input Validation Tests
  it("Invalid '=' Exception", () => {
    assert.throws(() => {
      b642packed("=F", undefined, undefined, -1);
    }, "Invalid '=' found in base-64 string");
  });
  it("Invalid Character Exception", () => {
    assert.throws(() => {
      b642packed("$", undefined, undefined, -1);
    }, "Invalid character in base-64 string");
  });
});

describe("Test uint8array2packed", () => {
  const uint8array2packed = converters.__get__("uint8array2packed");

  toPackedTestsBuilder(uint8array2packed, "uint8Array");
});

describe("Test arrayBuffer2packed", () => {
  const arraybuffer2packed = converters.__get__("arraybuffer2packed");

  toPackedTestsBuilder(arraybuffer2packed, "arrayBuffer");
});

describe("Test bytes2packed", () => {
  const bytes2packed = converters.__get__("bytes2packed"),
    shortBytes = String.fromCharCode(1, 2, 3),
    longBytes = String.fromCharCode(1, 2, 3, 4, 5);

  it("3-Byte Input - No Existing Input", () => {
    assert.deepEqual(bytes2packed(shortBytes, undefined, undefined, -1), {
      value: [0x01020300],
      binLen: 24,
    });
  });

  it("5-Byte Input - No Existing Input", () => {
    assert.deepEqual(bytes2packed(longBytes, undefined, undefined, -1), {
      value: [0x01020304, 0x05000000],
      binLen: 40,
    });
  });

  it("3-Byte Input - Existing Input", () => {
    assert.deepEqual(bytes2packed(shortBytes, [0x05000000], 8, -1), {
      value: [0x05010203],
      binLen: 32,
    });
  });

  it("5-Byte Input - Existing Input", () => {
    assert.deepEqual(bytes2packed(longBytes, [0x06000000], 8, -1), {
      value: [0x06010203, 0x04050000],
      binLen: 48,
    });
  });

  it("3-Byte Input - No Existing Input with Endian Modifier", () => {
    assert.deepEqual(bytes2packed(shortBytes, undefined, undefined, 1), {
      value: [0x00030201],
      binLen: 24,
    });
  });

  it("5-Byte Input - No Existing Input with Endian Modifier", () => {
    assert.deepEqual(bytes2packed(longBytes, undefined, undefined, 1), {
      value: [0x04030201, 0x00000005],
      binLen: 40,
    });
  });

  it("3-Byte Input - Existing Input with Endian Modifier", () => {
    assert.deepEqual(bytes2packed(shortBytes, [0x00000004], 8, 1), {
      value: [0x03020104],
      binLen: 32,
    });
  });

  it("5-Byte Input - Existing Input with Endian Modifier", () => {
    assert.deepEqual(bytes2packed(longBytes, [0x00000006], 8, 1), {
      value: [0x03020106, 0x00000504],
      binLen: 48,
    });
  });
});

describe("Test str2packed", () => {
  const str2packed = converters.__get__("str2packed"),
    toPackedTextTests = [
      {
        name: "'ABCDE' Input",
        inputs: {
          string: "ABCDE",
          existing: [0x46470000],
          existingMod: [0x00004746],
          lengthExisting: 16,
        },
        outputs: {
          utf8: [0x41424344, 0x45000000],
          utf8Mod: [0x44434241, 0x00000045],
          utf8Existing: [0x46474142, 0x43444500],
          lengthUtf8: 40,
          utf16le: [0x41004200, 0x43004400, 0x45000000],
          utf16leMod: [0x00420041, 0x00440043, 0x00000045],
          utf16leExisting: [0x46474100, 0x42004300, 0x44004500],
          utf16be: [0x00410042, 0x00430044, 0x00450000],
          utf16beMod: [0x42004100, 0x44004300, 0x00004500],
          utf16beExisting: [0x46470041, 0x00420043, 0x00440045],
          lengthUtf16: 80,
        },
      },
      {
        name: "U+00F1 Input (2 UTF-8 Bytes)",
        inputs: {
          string: "\u00F1",
          existing: [0x46470000],
          existingMod: [0x00004746],
          lengthExisting: 16,
        },
        outputs: {
          utf8: [0xc3b10000 | 0],
          utf8Mod: [0x0000b1c3],
          utf8Existing: [0x4647c3b1],
          lengthUtf8: 16,
          utf16le: [0xf1000000 | 0],
          utf16leMod: [0x000000f1 | 0],
          utf16leExisting: [0x4647f100],
          utf16be: [0x00f10000],
          utf16beMod: [0x0000f100],
          utf16beExisting: [0x464700f1],
          lengthUtf16: 16,
        },
      },
      {
        name: "U+1E4D Input (3 UTF-8 Bytes)",
        inputs: {
          string: "\u1E4D",
          existing: [0x46470000],
          existingMod: [0x00004746],
          lengthExisting: 16,
        },
        outputs: {
          utf8: [0xe1b98d00 | 0],
          utf8Mod: [0x008db9e1],
          utf8Existing: [0x4647e1b9, 0x8d000000 | 0],
          lengthUtf8: 24,
          utf16le: [0x4d1e0000],
          utf16leMod: [0x00001e4d],
          utf16leExisting: [0x46474d1e],
          utf16be: [0x1e4d0000],
          utf16beMod: [0x00004d1e],
          utf16beExisting: [0x46471e4d],
          lengthUtf16: 16,
        },
      },
      {
        name: "U+10348 Input (4 UTF-8 Bytes, 4 UTF-16 Bytes)",
        inputs: {
          string: "𐍈",
          existing: [0x46470000],
          existingMod: [0x00004746],
          lengthExisting: 16,
        },
        outputs: {
          utf8: [0xf0908d88 | 0],
          utf8Mod: [0x888d90f0 | 0],
          utf8Existing: [0x4647f090, 0x8d880000 | 0],
          lengthUtf8: 32,
          utf16le: [0x00d848df],
          utf16leMod: [0xdf48d800 | 0],
          utf16leExisting: [0x464700d8, 0x48df0000],
          utf16be: [0xd800df48 | 0],
          utf16beMod: [0x48df00d8 | 0],
          utf16beExisting: [0x4647d800, 0xdf480000 | 0],
          lengthUtf16: 32,
        },
      },
    ];

  toPackedTextTests.forEach((test) => {
    it(`${test.name} UTF8 - No Existing Input`, () => {
      assert.deepEqual(str2packed(test.inputs.string, "UTF8", undefined, undefined, -1), {
        value: test.outputs.utf8,
        binLen: test.outputs.lengthUtf8,
      });
    });
  });

  toPackedTextTests.forEach((test) => {
    it(`${test.name} UTF8 - No Existing Input With Endian Modifier`, () => {
      assert.deepEqual(str2packed(test.inputs.string, "UTF8", undefined, undefined, 1), {
        value: test.outputs.utf8Mod,
        binLen: test.outputs.lengthUtf8,
      });
    });
  });

  toPackedTextTests.forEach((test) => {
    it(`${test.name} UTF8 - Existing Input`, () => {
      assert.deepEqual(
        str2packed(test.inputs.string, "UTF8", test.inputs.existing.slice(), test.inputs.lengthExisting, -1),
        {
          value: test.outputs.utf8Existing,
          binLen: test.outputs.lengthUtf8 + test.inputs.lengthExisting,
        }
      );
    });
  });

  toPackedTextTests.forEach((test) => {
    it(`${test.name} UTF16LE - No Existing Input`, () => {
      assert.deepEqual(str2packed(test.inputs.string, "UTF16LE", undefined, undefined, -1), {
        value: test.outputs.utf16le,
        binLen: test.outputs.lengthUtf16,
      });
    });
  });

  toPackedTextTests.forEach((test) => {
    it(`${test.name} UTF16LE - No Existing Input with Endian Modifier`, () => {
      assert.deepEqual(str2packed(test.inputs.string, "UTF16LE", undefined, undefined, 1), {
        value: test.outputs.utf16leMod,
        binLen: test.outputs.lengthUtf16,
      });
    });
  });

  toPackedTextTests.forEach((test) => {
    it(`${test.name} UTF16LE - Existing Input`, () => {
      assert.deepEqual(
        str2packed(test.inputs.string, "UTF16LE", test.inputs.existing.slice(), test.inputs.lengthExisting, -1),
        {
          value: test.outputs.utf16leExisting,
          binLen: test.outputs.lengthUtf16 + test.inputs.lengthExisting,
        }
      );
    });
  });

  toPackedTextTests.forEach((test) => {
    it(`${test.name} UTF16BE - No Existing Input`, () => {
      assert.deepEqual(str2packed(test.inputs.string, "UTF16BE", undefined, undefined, -1), {
        value: test.outputs.utf16be,
        binLen: test.outputs.lengthUtf16,
      });
    });
  });

  toPackedTextTests.forEach((test) => {
    it(`${test.name} UTF16BE - No Existing Input with Endian Modifier`, () => {
      assert.deepEqual(str2packed(test.inputs.string, "UTF16BE", undefined, undefined, 1), {
        value: test.outputs.utf16beMod,
        binLen: test.outputs.lengthUtf16,
      });
    });
  });

  toPackedTextTests.forEach((test) => {
    it(`${test.name} UTF16BE - Existing Input`, () => {
      assert.deepEqual(
        str2packed(test.inputs.string, "UTF16BE", test.inputs.existing.slice(), test.inputs.lengthExisting, -1),
        {
          value: test.outputs.utf16beExisting,
          binLen: test.outputs.lengthUtf16 + test.inputs.lengthExisting,
        }
      );
    });
  });
});

// Input value to be reused across all the packed2* tests
const packedToInput = [0x00112233, 0xaabbccdd];

describe("Test packed2hex", () => {
  const packed2hex = converters.__get__("packed2hex");

  it("16-bit Input", () => {
    assert.equal(packed2hex(packedToInput, 16, -1, { outputUpper: false }), "0011");
  });
  it("64-bit Input", () => {
    assert.equal(packed2hex(packedToInput, 64, -1, { outputUpper: false }), "00112233aabbccdd");
  });
  it("64-bit Input with Output Uppercase", () => {
    assert.equal(packed2hex(packedToInput, 64, -1, { outputUpper: true }), "00112233AABBCCDD");
  });
  it("16-bit Input with Endian Modifier", () => {
    assert.equal(packed2hex(packedToInput, 16, 1, { outputUpper: false }), "3322");
  });
  it("64-bit with Endian Modifier", () => {
    assert.equal(packed2hex(packedToInput, 64, 1, { outputUpper: false }), "33221100ddccbbaa");
  });
});

describe("Test packed2b64", () => {
  const packed2b64 = converters.__get__("packed2b64");

  it("8-bit Input", () => {
    assert.equal(packed2b64(packedToInput, 8, -1, { b64Pad: "=" }), "AA==");
  });
  it("16-bit Input", () => {
    assert.equal(packed2b64(packedToInput, 16, -1, { b64Pad: "=" }), "ABE=");
  });
  it("64-bit Input", () => {
    assert.equal(packed2b64(packedToInput, 64, -1, { b64Pad: "=" }), "ABEiM6q7zN0=");
  });
  it("64-bit Input with # Pad", () => {
    assert.equal(packed2b64(packedToInput, 64, -1, { b64Pad: "#" }), "ABEiM6q7zN0#");
  });
  it("16-bit Input with Endian Modifier", () => {
    assert.equal(packed2b64(packedToInput, 16, 1, { b64Pad: "=" }), "MyI=");
  });
  it("64-bit with Endian Modifier", () => {
    assert.equal(packed2b64(packedToInput, 64, 1, { b64Pad: "=" }), "MyIRAN3Mu6o=");
  });
});

describe("Test packed2bytes", () => {
  const packed2bytes = converters.__get__("packed2bytes");

  it("16-bit Input", () => {
    assert.equal(packed2bytes(packedToInput, 16, -1), String.fromCharCode(0, 0x11));
  });
  it("64-bit Input", () => {
    assert.equal(packed2bytes(packedToInput, 64, -1), String.fromCharCode(0, 0x11, 0x22, 0x33, 0xaa, 0xbb, 0xcc, 0xdd));
  });
  it("16-bit Input with Endian Modifier", () => {
    assert.equal(packed2bytes(packedToInput, 16, 1), String.fromCharCode(0x33, 0x22));
  });
  it("64-bit with Endian Modifier", () => {
    assert.equal(packed2bytes(packedToInput, 64, 1), String.fromCharCode(0x33, 0x22, 0x11, 0, 0xdd, 0xcc, 0xbb, 0xaa));
  });
});

describe("Test packed2arraybuffer", () => {
  const packed2arraybuffer = converters.__get__("packed2arraybuffer");

  it("16-bit Input", () => {
    assert.deepEqual(packed2arraybuffer(packedToInput, 16, -1), newArrayBuffer([0, 0x11]));
  });
  it("64-bit Input", () => {
    assert.deepEqual(
      packed2arraybuffer(packedToInput, 64, -1),
      newArrayBuffer([0, 0x11, 0x22, 0x33, 0xaa, 0xbb, 0xcc, 0xdd])
    );
  });
  it("16-bit Input with Endian Modifier", () => {
    assert.deepEqual(packed2arraybuffer(packedToInput, 16, 1), newArrayBuffer([0x33, 0x22]));
  });
  it("64-bit with Endian Modifier", () => {
    assert.deepEqual(
      packed2arraybuffer(packedToInput, 64, 1),
      newArrayBuffer([0x33, 0x22, 0x11, 0, 0xdd, 0xcc, 0xbb, 0xaa])
    );
  });
});

describe("Test packed2uint8array", () => {
  const packed2uint8array = converters.__get__("packed2uint8array");

  it("16-bit Input", () => {
    assert.deepEqual(packed2uint8array(packedToInput, 16, -1), Uint8Array.from([0, 0x11]));
  });
  it("64-bit Input", () => {
    assert.deepEqual(
      packed2uint8array(packedToInput, 64, -1),
      Uint8Array.from([0, 0x11, 0x22, 0x33, 0xaa, 0xbb, 0xcc, 0xdd])
    );
  });
  it("16-bit Input with Endian Modifier", () => {
    assert.deepEqual(packed2uint8array(packedToInput, 16, 1), Uint8Array.from([0x33, 0x22]));
  });
  it("64-bit with Endian Modifier", () => {
    assert.deepEqual(
      packed2uint8array(packedToInput, 64, 1),
      Uint8Array.from([0x33, 0x22, 0x11, 0, 0xdd, 0xcc, 0xbb, 0xaa])
    );
  });
});

describe("Test packed2uint8array", () => {
  const packed2uint8array = converters.__get__("packed2uint8array");

  it("16-bit Input", () => {
    assert.deepEqual(packed2uint8array(packedToInput, 16, -1), Uint8Array.from([0, 0x11]));
  });
  it("64-bit Input", () => {
    assert.deepEqual(
      packed2uint8array(packedToInput, 64, -1),
      Uint8Array.from([0, 0x11, 0x22, 0x33, 0xaa, 0xbb, 0xcc, 0xdd])
    );
  });
  it("16-bit Input with Endian Modifier", () => {
    assert.deepEqual(packed2uint8array(packedToInput, 16, 1), Uint8Array.from([0x33, 0x22]));
  });
  it("64-bit with Endian Modifier", () => {
    assert.deepEqual(
      packed2uint8array(packedToInput, 64, 1),
      Uint8Array.from([0x33, 0x22, 0x11, 0, 0xdd, 0xcc, 0xbb, 0xaa])
    );
  });
});

describe("Test getStrConverter", () => {
  let revert, strConverter;

  // getStrConverter is actually exported but mixing rewire and sinon imports causes a node.js core dump
  const getStrConverter = converters.__get__("getStrConverter"),
    funcNameToInputValueMappings = [
      { inputValue: "HEX", funcName: "hex2packed" },
      { inputValue: "B64", funcName: "b642packed" },
      { inputValue: "BYTES", funcName: "bytes2packed" },
      { inputValue: "ARRAYBUFFER", funcName: "arraybuffer2packed" },
      { inputValue: "UINT8ARRAY", funcName: "uint8array2packed" },
    ];

  funcNameToInputValueMappings.forEach((mapping) => {
    it(`${mapping.funcName} Mapping`, () => {
      const spy = sinon.spy();
      revert = converters.__set__(mapping.funcName, spy);
      strConverter = getStrConverter(mapping.inputValue, "UTF8", -1);
      strConverter("00", [], 0);
      assert.isTrue(spy.calledWithExactly("00", [], 0, -1));
      revert();
    });
  });

  // Needed to be handled separately due to utf type being passed into eventual function
  it("str2packed Mapping", () => {
    const spy = sinon.spy();
    converters.__with__({ str2packed: spy })(() => {
      strConverter = getStrConverter("TEXT", "UTF8", -1);
      strConverter("00", [], 0);
      assert.isTrue(spy.calledWithExactly("00", "UTF8", [], 0, -1));
    });
  });

  it("Invalid UTF Exception", () => {
    assert.throws(() => {
      // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
      // @ts-ignore - Deliberate bad UTF value to test exceptions
      getStrConverter("HEX", "UTF32", -1);
    }, "encoding must be UTF8, UTF16BE, or UTF16LE");
  });

  it("Invalid Input Type", () => {
    assert.throws(() => {
      getStrConverter("GARBAGE", "UTF8", -1);
    }, "format must be HEX, TEXT, B64, BYTES, ARRAYBUFFER, or UINT8ARRAY");
  });

  it("arraybuffer2packed Unsupported", () => {
    converters.__with__({ ArrayBuffer: sinon.stub().throws() })(() => {
      assert.throws(() => {
        getStrConverter("ARRAYBUFFER", "UTF8", -1);
      }, "ARRAYBUFFER not supported by this environment");
    });
  });

  it("uint8array2packed Unsupported", () => {
    converters.__with__({ Uint8Array: sinon.stub().throws() })(() => {
      assert.throws(() => {
        getStrConverter("UINT8ARRAY", "UTF8", -1);
      }, "UINT8ARRAY not supported by this environment");
    });
  });
});

describe("Test getOutputConverter", () => {
  let spy, revert, outputConverter;

  // getOutputConverter is actually exported but mixing rewire and sinon imports causes a node.js core dump
  const getOutputConverter = converters.__get__("getOutputConverter"),
    funcNameToInputValueMappings = [
      { inputValue: "HEX", funcName: "packed2hex", needsOptions: true },
      { inputValue: "B64", funcName: "packed2b64", needsOptions: true },
      { inputValue: "BYTES", funcName: "packed2bytes", needsOptions: false },
      { inputValue: "ARRAYBUFFER", funcName: "packed2arraybuffer", needsOptions: false },
      { inputValue: "UINT8ARRAY", funcName: "packed2uint8array", needsOptions: false },
    ],
    options = { outputUpper: false, b64Pad: "", outputLen: -1 };

  funcNameToInputValueMappings.forEach((mapping) => {
    it(`${mapping.funcName} Mapping`, () => {
      spy = sinon.spy();
      revert = converters.__set__(mapping.funcName, spy);
      outputConverter = getOutputConverter(mapping.inputValue, 0, -1, options);
      outputConverter([0]);
      if (mapping.needsOptions === true) {
        assert.isTrue(spy.calledWithExactly([0], 0, -1, options));
      } else {
        assert.isTrue(spy.calledWithExactly([0], 0, -1));
      }
      revert();
    });
  });

  it("Invalid Input Type", () => {
    assert.throws(() => {
      getOutputConverter("GARBAGE", -1, -1, options);
    }, "HEX, B64, BYTES, ARRAYBUFFER, or UINT8ARRAY");
  });

  it("arraybuffer2packed Unsupported", () => {
    converters.__with__({ ArrayBuffer: sinon.stub().throws() })(() => {
      assert.throws(() => {
        getOutputConverter("ARRAYBUFFER", 0, -1, options);
      }, "ARRAYBUFFER not supported by this environment");
    });
  });

  it("uint8array2packed Unsupported", () => {
    converters.__with__({ Uint8Array: sinon.stub().throws() })(() => {
      assert.throws(() => {
        getOutputConverter("UINT8ARRAY", 0, -1, options);
      }, "UINT8ARRAY not supported by this environment");
    });
  });
});
