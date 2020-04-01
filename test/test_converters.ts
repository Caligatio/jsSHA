import { describe, it } from "mocha";
import rewire from "rewire";
import { assert } from "chai";
import { packedValue } from "../src/converters";

const converters = rewire("../src/converters");

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
  funcToTest: (input: any, existingBin: number[] | undefined, existingBinLen: number | undefined, bigEndianMod: -1 | 1) => packedValue,
  inputType: "hex" | "b64" | "arrayBuffer" | "uint8Array"
) {
  toPackedTests.forEach((test) => {
    it(`${test.name} - No Existing Input`, () => {
      assert.deepEqual(funcToTest(test.inputs[inputType], undefined, undefined, -1), {
        value: test.outputs.original,
        binLen: test.outputs.length,
      });
    });
    it(`${test.name} - Existing Input`, () => {
      assert.deepEqual(funcToTest(test.inputs[inputType], test.inputs.existing.slice(), test.inputs.lengthExisting, -1), {
        value: test.outputs.existing,
        binLen: test.outputs.length + test.inputs.lengthExisting,
      });
    });
    it(`${test.name} - No Existing Input with Endian Modifier`, () => {
      assert.deepEqual(funcToTest(test.inputs[inputType], undefined, undefined, 1), {
        value: test.outputs.originalMod,
        binLen: test.outputs.length,
      });
    });
    it(`${test.name} - Existing Input with Endian Modifier`, () => {
      assert.deepEqual(funcToTest(test.inputs[inputType], test.inputs.existingMod.slice(), test.inputs.lengthExisting, 1), {
        value: test.outputs.existingMod,
        binLen: test.outputs.length + test.inputs.lengthExisting,
      });
    });
  });
}

describe("Test hex2packed", () => {
  const hex2packed = converters.__get__("hex2packed");

  // Basic I/O tests
  toPackedTestsBuilder(hex2packed, "hex");

  // Input Validation Tests
  it("Invalid Length Exception", function () {
    assert.throws(() => {
      hex2packed("F", undefined, undefined, -1);
    }, "String of HEX type must be in byte increments");
  });
  it("Invalid Character Exception", function () {
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
  it("Invalid '=' Exception", function () {
    assert.throws(() => {
      b642packed("=F", undefined, undefined, -1);
    }, "Invalid '=' found in base-64 string");
  });
  it("Invalid Character Exception", function () {
    assert.throws(() => {
      b642packed("$", undefined, undefined, -1);
    }, "Invalid character in base-64 string");
  });
});

describe("Test uint8array2packed", () => {
  const uint8array2packed = converters.__get__("uint8array2packed");

  // Basic I/O tests
  toPackedTestsBuilder(uint8array2packed, "uint8Array");
});

describe("Test arrayBuffer2packed", () => {
  const arraybuffer2packed = converters.__get__("arraybuffer2packed");

  // Basic I/O tests
  toPackedTestsBuilder(arraybuffer2packed, "arrayBuffer");
});


describe("Test bytes2packed", () => {
  const bytes2packed = converters.__get__("bytes2packed"), shortBytes = String.fromCharCode(1, 2, 3), longBytes = String.fromCharCode(1, 2, 3, 4, 5);

  it("Short Bytes - No Existing Input", () => {
    assert.deepEqual(bytes2packed(shortBytes, undefined, undefined, -1), {
      value: [0x01020300],
      binLen: 24,
    });
  });

  it("Long Bytes - No Existing Input", () => {
    assert.deepEqual(bytes2packed(longBytes, undefined, undefined, -1), {
      value: [0x01020304, 0x05000000],
      binLen: 40,
    });
  });

  it("Short Bytes - Existing Input", () => {
    assert.deepEqual(bytes2packed(shortBytes, [0x05000000], 8, -1), {
      value: [0x05010203],
      binLen: 32,
    });
  });

  it("Long Bytes - Existing Input", () => {
    assert.deepEqual(bytes2packed(longBytes, [0x06000000], 8, -1), {
      value: [0x06010203, 0x04050000],
      binLen: 48,
    });
  });

  it("Short Bytes - No Existing Input with Endian Modifier", () => {
    assert.deepEqual(bytes2packed(shortBytes, undefined, undefined, 1), {
      value: [0x00030201],
      binLen: 24,
    });
  });

  it("Long Bytes - No Existing Input with Endian Modifier", () => {
    assert.deepEqual(bytes2packed(longBytes, undefined, undefined, 1), {
      value: [0x04030201, 0x00000005],
      binLen: 40,
    });
  });

  it("Short Bytes - Existing Input with Endian Modifier", () => {
    assert.deepEqual(bytes2packed(shortBytes, [0x00000004], 8, 1), {
      value: [0x03020104],
      binLen: 32,
    });
  });

  it("Long Bytes - Existing Input with Endian Modifier", () => {
    assert.deepEqual(bytes2packed(longBytes, [0x00000006], 8, 1), {
      value: [0x03020106, 0x00000504],
      binLen: 48,
    });
  });
});

const toPackedTextTests = [
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
      utf8: [0xC3B10000 | 0],
      utf8Mod: [0x0000B1C3],
      utf8Existing: [0x4647C3B1],
      lengthUtf8: 16,
      utf16le: [0xF1000000 | 0],
      utf16leMod: [0x000000F1 | 0],
      utf16leExisting: [0x4647F100],
      utf16be: [0x00F10000],
      utf16beMod: [0x0000F100],
      utf16beExisting: [0x464700F1],
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
      utf8: [0xE1B98D00 | 0],
      utf8Mod: [0x008DB9E1],
      utf8Existing: [0x4647E1B9, 0x8D000000 | 0],
      lengthUtf8: 24,
      utf16le: [0x4D1E0000],
      utf16leMod: [0x00001E4D],
      utf16leExisting: [0x46474D1E],
      utf16be: [0x1E4D0000],
      utf16beMod: [0x00004D1E],
      utf16beExisting: [0x46471E4D],
      lengthUtf16: 16,
    }
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
      utf8: [0xF0908D88 | 0],
      utf8Mod: [0x888D90F0 | 0],
      utf8Existing: [0x4647F090, 0x8D880000 | 0],
      lengthUtf8: 32,
      utf16le: [0x00D848DF],
      utf16leMod: [0xDF48D800 | 0],
      utf16leExisting: [0x464700D8, 0x48DF0000],
      utf16be: [0xD800DF48 | 0],
      utf16beMod: [0x48DF00D8 | 0],
      utf16beExisting: [0x4647D800, 0xDF480000 | 0],
      lengthUtf16: 32,
    },
  },
];

describe("Test str2packed", () => {
  const str2packed = converters.__get__("str2packed");

  // Basic I/O tests
  toPackedTextTests.forEach((test) => {
    it(`${test.name} UTF8 - No Existing Input`, () => {
      assert.deepEqual(str2packed(test.inputs.string, "UTF8", undefined, undefined, -1), {
        value: test.outputs.utf8,
        binLen: test.outputs.lengthUtf8
      });
    });
  });

  toPackedTextTests.forEach((test) => {
    it(`${test.name} UTF8 - No Existing Input With Endian Modifier`, () => {
      assert.deepEqual(str2packed(test.inputs.string, "UTF8", undefined, undefined, 1), {
        value: test.outputs.utf8Mod,
        binLen: test.outputs.lengthUtf8
      });
    });
  });

  toPackedTextTests.forEach((test) => {
    it(`${test.name} UTF8 - Existing Input`, () => {
      assert.deepEqual(str2packed(test.inputs.string, "UTF8", test.inputs.existing.slice(), test.inputs.lengthExisting, -1), {
        value: test.outputs.utf8Existing,
        binLen: test.outputs.lengthUtf8 + test.inputs.lengthExisting
      });
    });
  });

  toPackedTextTests.forEach((test) => {
    it(`${test.name} UTF16LE - No Existing Input`, () => {
      assert.deepEqual(str2packed(test.inputs.string, "UTF16LE", undefined, undefined, -1), {
        value: test.outputs.utf16le,
        binLen: test.outputs.lengthUtf16
      });
    });
  });

  toPackedTextTests.forEach((test) => {
    it(`${test.name} UTF16LE - No Existing Input with Endian Modifier`, () => {
      assert.deepEqual(str2packed(test.inputs.string, "UTF16LE", undefined, undefined, 1), {
        value: test.outputs.utf16leMod,
        binLen: test.outputs.lengthUtf16
      });
    });
  });

  toPackedTextTests.forEach((test) => {
    it(`${test.name} UTF16LE - Existing Input`, () => {
      assert.deepEqual(str2packed(test.inputs.string, "UTF16LE", test.inputs.existing.slice(), test.inputs.lengthExisting, -1), {
        value: test.outputs.utf16leExisting,
        binLen: test.outputs.lengthUtf16 + test.inputs.lengthExisting
      });
    });
  });

  toPackedTextTests.forEach((test) => {
    it(`${test.name} UTF16BE - No Existing Input`, () => {
      assert.deepEqual(str2packed(test.inputs.string, "UTF16BE", undefined, undefined, -1), {
        value: test.outputs.utf16be,
        binLen: test.outputs.lengthUtf16
      });
    });
  });

  toPackedTextTests.forEach((test) => {
    it(`${test.name} UTF16BE - No Existing Input with Endian Modifier`, () => {
      assert.deepEqual(str2packed(test.inputs.string, "UTF16BE", undefined, undefined, 1), {
        value: test.outputs.utf16beMod,
        binLen: test.outputs.lengthUtf16
      });
    });
  });

  toPackedTextTests.forEach((test) => {
    it(`${test.name} UTF16BE - Existing Input`, () => {
      assert.deepEqual(str2packed(test.inputs.string, "UTF16BE", test.inputs.existing.slice(), test.inputs.lengthExisting, -1), {
        value: test.outputs.utf16beExisting,
        binLen: test.outputs.lengthUtf16 + test.inputs.lengthExisting
      });
    });
  });
});
