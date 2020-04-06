import { describe, it } from "mocha";
import { assert } from "chai";
import {
  ch_32,
  gamma0_32,
  gamma1_32,
  maj_32,
  parity_32,
  rotl_32,
  safeAdd_32_2,
  safeAdd_32_4,
  safeAdd_32_5,
  sigma0_32,
  sigma1_32,
} from "../../src/primitives_32";
import rewire from "rewire";

const primitives_32 = rewire("../../src/primitives_32");

describe("Test rotl_32", () => {
  it("With Wrap Around", () => {
    assert.equal(rotl_32(0x00aabb00, 16), 0xbb0000aa | 0);
  });

  it("Without Wrap Around", () => {
    assert.equal(rotl_32(0x0000aabb, 16), 0xaabb0000 | 0);
  });
});

describe("Test rotr_32", () => {
  const rotr_32 = primitives_32.__get__("rotr_32");

  it("With Wrap Around", () => {
    assert.equal(rotr_32(0x00aabb00, 16), 0xbb0000aa | 0);
  });

  it("Without Wrap Around", () => {
    assert.equal(rotr_32(0xaabb0000 | 0, 16), 0x0000aabb);
  });
});

describe("Test shr_32", () => {
  const shr_32 = primitives_32.__get__("shr_32");

  it("With Wrap Around", () => {
    assert.equal(shr_32(0x00aabb00, 16), 0x000000aa);
  });

  it("Without Wrap Around", () => {
    assert.equal(shr_32(0xaabb0000 | 0, 16), 0x0000aabb);
  });
});

describe("Test parity_32", () => {
  it("With Valid Inputs", () => {
    assert.equal(parity_32(0x55555555, 0xaaaaaaaa | 0, 0x00ffff00), 0xff0000ff | 0);
  });
});

describe("Test ch_32", () => {
  it("With Valid Inputs", () => {
    assert.equal(ch_32(0x55555555, 0xaaaaaaaa | 0, 0x00ffff00), 0x00aaaa00);
  });
});

describe("Test maj_32", () => {
  it("With Valid Inputs", () => {
    assert.equal(maj_32(0x55555555, 0x0000ff00, 0x000000ff), 0x00005555);
  });
});

describe("Test sigma0_32", () => {
  it("With Valid Inputs", () => {
    assert.equal(sigma0_32(0xaabbccdd), 0xe370d043 | 0);
  });
});

describe("Test sigma1_32", () => {
  it("With Valid Inputs", () => {
    assert.equal(sigma1_32(0xaabbccdd), 0xb0f9d69f | 0);
  });
});

describe("Test gamma0_32", () => {
  it("With Valid Inputs", () => {
    assert.equal(gamma0_32(0xaabbccdd), 0x5d3564ac);
  });
});

describe("Test gamma1_32", () => {
  it("With Valid Inputs", () => {
    assert.equal(gamma1_32(0xaabbccdd), 0x9fdfcef9 | 0);
  });
});

describe("Test safeAdd_32_2", () => {
  it("With Only Positive Integers", () => {
    assert.equal(safeAdd_32_2(0x01aa0000, 0x0100bb00), 0x02aabb00);
  });

  it("With Only Negative Integers", () => {
    assert.equal(safeAdd_32_2(0x81aa0000, 0x8100bb00), 0x02aabb00);
  });

  it("With Mixed Integer Signs", () => {
    assert.equal(safeAdd_32_2(0x81aa0000, 0x0100bb00), 0x82aabb00 | 0);
  });
});

describe("Test safeAdd_32_4", () => {
  it("With Only Positive Integers", () => {
    assert.equal(safeAdd_32_4(0x01aa0000, 0x0100bb00, 0x010000cc, 0x01000011), 0x04aabbdd);
  });

  it("With Only Negative Integers", () => {
    assert.equal(safeAdd_32_4(0x81aa0000 | 0, 0x8100bb00 | 0, 0x810000cc | 0, 0x81000011 | 0), 0x04aabbdd);
  });

  it("With Mixed Integer Signs", () => {
    assert.equal(safeAdd_32_4(0x81aa0000 | 0, 0x0100bb00, 0x010000cc, 0x01000011), 0x84aabbdd | 0);
  });
});

describe("Test safeAdd_32_5", () => {
  it("With Only Positive Integers", () => {
    assert.equal(safeAdd_32_5(0x01aa0000, 0x0100bb00, 0x010000cc, 0x01000011, 0x01000011), 0x05aabbee);
  });

  it("With Only Negative Integers", () => {
    assert.equal(
      safeAdd_32_5(0x81aa0000 | 0, 0x8100bb00 | 0, 0x810000cc | 0, 0x81000011 | 0, 0x81000011),
      0x85aabbee | 0
    );
  });

  it("With Mixed Integer Signs", () => {
    assert.equal(safeAdd_32_5(0x81aa0000 | 0, 0x0100bb00, 0x010000cc, 0x01000011, 0x01000011), 0x85aabbee | 0);
  });
});
