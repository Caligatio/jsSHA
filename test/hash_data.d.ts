/* This file was manually created so there may be more efficient ways of defining this */

export as namespace hashData;

interface testTextInput {
  type: "TEXT";
  value: string;
  encoding?: "UTF8";
  rounds?: number;
}

interface testHexKey {
  type: "HEX";
  value: string;
}

interface testHexOutut {
  type: "HEX";
  value: string;
  shakeLen?: number;
}

interface test {
  name: string;
  input: testTextInput;
  key?: testHexKey;
  outputs: testHexOutut[];
}

declare const hash_data: {
  "SHA-1": test[];
  "SHA-224": test[];
  "SHA3-224": test[];
  "SHA-256": test[];
  "SHA3-256": test[];
  "SHA-384": test[];
  "SHA3-384": test[];
  "SHA-512": test[];
  "SHA3-512": test[];
  SHAKE128: test[];
  SHAKE256: test[];
};

export = hash_data;
