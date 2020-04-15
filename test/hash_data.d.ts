/* This file was manually created so there may be more efficient ways of defining this */

export as namespace hashData;

interface testTextInput {
  format: "TEXT";
  value: string;
  encoding?: "UTF8";
  rounds?: number;
}

interface testHexKey {
  format: "HEX";
  value: string;
}

interface testTextCustomization {
  format: "TEXT";
  value: string;
}

interface testHexOutut {
  format: "HEX";
  value: string;
  outputLen?: number;
}

interface test {
  name: string;
  input: testTextInput;
  hmacKey?: testHexKey;
  kmacKey?: testHexKey;
  customization?: testTextCustomization;
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
  CSHAKE128: test[];
  CSHAKE256: test[];
  KMAC128: test[];
  KMAC256: test[];
};

export = hash_data;
