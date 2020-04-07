import { describe, it } from "mocha";
import { assert } from "chai";
import {
  Int_64,
  rotl_64,
  ch_64,
  gamma0_64,
  gamma1_64,
  maj_64,
  sigma0_64,
  sigma1_64,
  safeAdd_64_2,
  safeAdd_64_4,
  safeAdd_64_5,
  xor_64_2,
  xor_64_5,
} from "../../src/primitives_64";
import rewire from "rewire";

const primitives_64 = rewire("../../src/primitives_64");

describe("Test Int_64", () => {
  const int64 = new Int_64(0xdeadbeef, 0xfacefeed);

  it("Stored Values", () => {
    assert.deepEqual(int64, { highOrder: 0xdeadbeef, lowOrder: 0xfacefeed });
  });
});

describe("Test rotl_64", () => {
  const int64 = new Int_64(0x11223344, 0x55667788);

  it("Rotate by 0", () => {
    assert.deepEqual(rotl_64(int64, 0), int64);
  });

  it("Rotate by 16", () => {
    assert.deepEqual(rotl_64(int64, 16), { highOrder: 0x33445566, lowOrder: 0x77881122 });
  });

  it("Rotate by 48", () => {
    assert.deepEqual(rotl_64(int64, 48), { highOrder: 0x77881122, lowOrder: 0x33445566 });
  });
});

describe("Test rotr_64", () => {
  const int64 = new Int_64(0x11223344, 0x55667788),
    rotr_64 = primitives_64.__get__("rotr_64");

  it("Rotate by 16", () => {
    assert.deepEqual(rotr_64(int64, 16), { highOrder: 0x77881122, lowOrder: 0x33445566 });
  });

  it("Rotate by 48", () => {
    assert.deepEqual(rotr_64(int64, 48), { highOrder: 0x33445566, lowOrder: 0x77881122 });
  });
});

describe("Test shr_64", () => {
  const int64 = new Int_64(0x11223344, 0x55667788),
    shr_64 = primitives_64.__get__("shr_64");

  it("Shift by 16", () => {
    assert.deepEqual(shr_64(int64, 16), { highOrder: 0x00001122, lowOrder: 0x33445566 });
  });
});

describe("Test ch_64", () => {
  it("With Valid Inputs", () => {
    assert.deepEqual(
      ch_64(new Int_64(0x55555555, 0x55555555), new Int_64(0xaaaaaaaa, 0xaaaaaaaa), new Int_64(0x00ffff00, 0x00ffff00)),
      new Int_64(0x00aaaa00, 0x00aaaa00)
    );
  });
});

describe("Test maj_64", () => {
  it("With Valid Inputs", () => {
    assert.deepEqual(
      maj_64(
        new Int_64(0x55555555, 0x55555555),
        new Int_64(0x0000ff00, 0x0000ff00),
        new Int_64(0x000000ff, 0x000000ff)
      ),
      new Int_64(0x00005555, 0x00005555)
    );
  });
});

describe("Test sigma0_64", () => {
  it("With Valid Inputs", () => {
    assert.deepEqual(sigma0_64(new Int_64(0x66778899, 0xaabbccdd)), new Int_64(0xf2474978 | 0, 0x842984ad | 0));
  });
});

describe("Test sigma1_64", () => {
  it("With Valid Inputs", () => {
    assert.deepEqual(sigma1_64(new Int_64(0x66778899, 0xaabbccdd)), new Int_64(0x8c979da5 | 0, 0xaef3fb85 | 0));
  });
});

describe("Test safeAdd_64_2", () => {
  it("With Only Positive Integers", () => {
    assert.deepEqual(
      safeAdd_64_2(new Int_64(0x01aa0000, 0x01bb0000), new Int_64(0x0100cc00, 0x0100dd00)),
      new Int_64(0x02aacc00, 0x02bbdd00)
    );
  });

  it("With Only Negative Integers", () => {
    assert.deepEqual(
      safeAdd_64_2(new Int_64(0x81aa0000, 0x81bb0000), new Int_64(0x8100cc00, 0x8100dd00)),
      new Int_64(0x02aacc01, 0x02bbdd00)
    );
  });

  it("With Mixed Integer Signs", () => {
    assert.deepEqual(
      safeAdd_64_2(new Int_64(0x81aa0000, 0x01bb0000), new Int_64(0x0100cc00, 0x8100dd00)),
      new Int_64(0x82aacc00 | 0, 0x82bbdd00 | 0)
    );
  });
});

describe("Test safeAdd_64_4", () => {
  it("With Only Positive Integers", () => {
    assert.deepEqual(
      safeAdd_64_4(
        new Int_64(0x01110000, 0x01220000),
        new Int_64(0x01003300, 0x01004400),
        new Int_64(0x01000055, 0x01000066),
        new Int_64(0x01000077, 0x01000088)
      ),
      new Int_64(0x041133cc, 0x042244ee)
    );
  });

  it("With Only Negative Integers", () => {
    assert.deepEqual(
      safeAdd_64_4(
        new Int_64(0x81110000, 0x81220000),
        new Int_64(0x81003300, 0x81004400),
        new Int_64(0x81000055, 0x81000066),
        new Int_64(0x81000077, 0x81000088)
      ),
      new Int_64(0x041133ce, 0x042244ee)
    );
  });

  it("With Mixed Integer Signs", () => {
    assert.deepEqual(
      safeAdd_64_4(
        new Int_64(0x01110000, 0x01220000),
        new Int_64(0x81003300, 0x81004400),
        new Int_64(0x81000055, 0x81000066),
        new Int_64(0x81000077, 0x81000088)
      ),
      new Int_64(0x841133cd | 0, 0x842244ee | 0)
    );
  });
});

describe("Test safeAdd_64_5", () => {
  it("With Only Positive Integers", () => {
    assert.deepEqual(
      safeAdd_64_5(
        new Int_64(0x01110000, 0x01220000),
        new Int_64(0x01003300, 0x01004400),
        new Int_64(0x01000055, 0x01000066),
        new Int_64(0x01000077, 0x01000088),
        new Int_64(0x01110000, 0x01002200)
      ),
      new Int_64(0x052233cc, 0x052266ee)
    );
  });

  it("With Only Negative Integers", () => {
    assert.deepEqual(
      safeAdd_64_5(
        new Int_64(0x81110000, 0x81220000),
        new Int_64(0x81003300, 0x81004400),
        new Int_64(0x81000055, 0x81000066),
        new Int_64(0x81000077, 0x81000088),
        new Int_64(0x81110000, 0x81002200)
      ),
      new Int_64(0x852233ce | 0, 0x852266ee | 0)
    );
  });

  it("With Mixed Integer Signs", () => {
    assert.deepEqual(
      safeAdd_64_5(
        new Int_64(0x01110000, 0x01220000),
        new Int_64(0x81003300, 0x81004400),
        new Int_64(0x81000055, 0x81000066),
        new Int_64(0x81000077, 0x81000088),
        new Int_64(0x01110000, 0x01002200)
      ),
      new Int_64(0x852233cd | 0, 0x852266ee | 0)
    );
  });
});

describe("Test xor_64_2", () => {
  it("With Valid Inputs", () => {
    assert.deepEqual(
      xor_64_2(new Int_64(0x00000000, 0x55555555), new Int_64(0x11111111, 0xaaaaaaaa)),
      new Int_64(0x11111111, 0xffffffff | 0)
    );
  });
});

describe("Test xor_64_5", () => {
  it("With Valid Inputs", () => {
    assert.deepEqual(
      xor_64_5(
        new Int_64(0x00000000, 0x55555555),
        new Int_64(0x11111111, 0xaaaaaaaa),
        new Int_64(0x88888888, 0x11111111),
        new Int_64(0x33333333, 0x88888888),
        new Int_64(0x44444444, 0x22222222)
      ),
      new Int_64(0xeeeeeeee | 0, 0x44444444)
    );
  });
});

describe("Test gamma0_64", () => {
  it("With Valid Inputs", () => {
    assert.deepEqual(gamma0_64(new Int_64(0x11223344, 0x55667788)), new Int_64(0x80a27ff7 | 0, 0xe64c915c | 0));
  });
});

describe("Test gamma1_64", () => {
  it("With Valid Inputs", () => {
    assert.deepEqual(gamma1_64(new Int_64(0x11223344, 0x55667788)), new Int_64(0x47a410cb, 0xfc0eaf32 | 0));
  });
});
