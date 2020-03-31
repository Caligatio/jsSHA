import { packedValue, getStrConverter, getOutputConverter } from "./converters";

export const TWO_PWR_32 = 4294967296;

/* Constant used in SHA-2 families */
export const K_sha2 = [
  0x428a2f98,
  0x71374491,
  0xb5c0fbcf,
  0xe9b5dba5,
  0x3956c25b,
  0x59f111f1,
  0x923f82a4,
  0xab1c5ed5,
  0xd807aa98,
  0x12835b01,
  0x243185be,
  0x550c7dc3,
  0x72be5d74,
  0x80deb1fe,
  0x9bdc06a7,
  0xc19bf174,
  0xe49b69c1,
  0xefbe4786,
  0x0fc19dc6,
  0x240ca1cc,
  0x2de92c6f,
  0x4a7484aa,
  0x5cb0a9dc,
  0x76f988da,
  0x983e5152,
  0xa831c66d,
  0xb00327c8,
  0xbf597fc7,
  0xc6e00bf3,
  0xd5a79147,
  0x06ca6351,
  0x14292967,
  0x27b70a85,
  0x2e1b2138,
  0x4d2c6dfc,
  0x53380d13,
  0x650a7354,
  0x766a0abb,
  0x81c2c92e,
  0x92722c85,
  0xa2bfe8a1,
  0xa81a664b,
  0xc24b8b70,
  0xc76c51a3,
  0xd192e819,
  0xd6990624,
  0xf40e3585,
  0x106aa070,
  0x19a4c116,
  0x1e376c08,
  0x2748774c,
  0x34b0bcb5,
  0x391c0cb3,
  0x4ed8aa4a,
  0x5b9cca4f,
  0x682e6ff3,
  0x748f82ee,
  0x78a5636f,
  0x84c87814,
  0x8cc70208,
  0x90befffa,
  0xa4506ceb,
  0xbef9a3f7,
  0xc67178f2,
];

/* Constant used in SHA-2 families */
export const H_trunc = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];

/* Constant used in SHA-2 families */
export const H_full = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

/**
 * Validate hash list containing output formatting options, ensuring
 * presence of every option or adding the default value
 *
 * @param options Hash list of output formatting options
 * @returns Validated
 *   hash list containing output formatting options
 */
export function getOutputOpts(options?: {
  outputUpper?: boolean;
  b64Pad?: string;
  shakeLen?: number;
}): { outputUpper: boolean; b64Pad: string; shakeLen: number; } {
  let retVal = { outputUpper: false, b64Pad: "=", shakeLen: -1 },
    outputOptions: { outputUpper?: boolean; b64Pad?: string; shakeLen?: number; };
  outputOptions = options || {};

  retVal["outputUpper"] = outputOptions["outputUpper"] || false;

  if (outputOptions["b64Pad"]) {
    retVal["b64Pad"] = outputOptions["b64Pad"];
  }

  if (outputOptions["shakeLen"]) {
    if (outputOptions["shakeLen"] % 8 !== 0) {
      throw new Error("shakeLen must be a multiple of 8");
    }
    retVal["shakeLen"] = outputOptions["shakeLen"];
  }

  if ("boolean" !== typeof retVal["outputUpper"]) {
    throw new Error("Invalid outputUpper formatting option");
  }

  if ("string" !== typeof retVal["b64Pad"]) {
    throw new Error("Invalid b64Pad formatting option");
  }

  return retVal;
}

export abstract class jsSHABase<StateType, VariantTypes> {
  /* Needed inputs */
  shaVariant: VariantTypes;
  inputFormat: "HEX" | "TEXT" | "B64" | "BYTES" | "ARRAYBUFFER" | "UINT8ARRAY"
  inputOptions: { encoding?: "UTF8" | "UTF16BE" | "UTF16LE"; numRounds?: number };
  utfType: "UTF8" | "UTF16BE" | "UTF16LE";
  numRounds: number;

  /* State */
  abstract intermediateState: StateType;
  keyWithIPad: number[];
  keyWithOPad: number[];
  remainder: number[];
  remainderLen: number;
  updatedCalled: boolean;
  processedLen: number;
  hmacKeySet: boolean;

  /* Variant specifics */
  abstract variantBlockSize: number;
  abstract bigEndianMod: -1 | 1;
  abstract outputBinLen: number;

  /* Functions */
  abstract converterFunc: (input: any, existingBin: number[], existingBinLen: number) => packedValue;
  abstract roundFunc: (block: number[], H: StateType) => StateType;
  abstract finalizeFunc: (
    remainder: number[],
    remainderBinLen: number,
    processedBinLen: number,
    H: StateType,
    _outputLen: number
  ) => number[];
  abstract stateCloneFunc: (state: StateType) => StateType;
  abstract newStateFunc: (variant: VariantTypes) => StateType;

  constructor(
    variant: VariantTypes,
    inputFormat: "HEX" | "TEXT" | "B64" | "BYTES" | "ARRAYBUFFER" | "UINT8ARRAY",
    options?: { encoding?: "UTF8" | "UTF16BE" | "UTF16LE"; numRounds?: number }
  ) {
    this.inputFormat = inputFormat
    this.inputOptions = options || {};
    this.utfType = this.inputOptions["encoding"] || "UTF8";
    this.numRounds = this.inputOptions["numRounds"] || 1;

    // @ts-ignore - Need to use parseInt as a type-check
    if (this.numRounds !== parseInt(this.numRounds, 10) || 1 > this.numRounds) {
      throw new Error("numRounds must a integer >= 1");
    }

    this.shaVariant = variant;
    this.remainder = [];
    this.remainderLen = 0;
    this.updatedCalled = false;
    this.processedLen = 0;
    this.hmacKeySet = false;
    this.keyWithIPad = [];
    this.keyWithOPad = [];
  }

  /**
   * Takes strString and hashes as many blocks as possible.  Stores the
   * rest for either a future update or getHash call.
   *
   * @param srcString The string to be hashed
   */
  update(srcString: string | ArrayBuffer | Uint8Array) {
    let convertRet,
      chunkBinLen,
      chunkIntLen,
      chunk,
      i,
      updateProcessedLen = 0,
      variantBlockIntInc = this.variantBlockSize >>> 5;

    convertRet = this.converterFunc(srcString, this.remainder, this.remainderLen);
    chunkBinLen = convertRet["binLen"];
    chunk = convertRet["value"];

    chunkIntLen = chunkBinLen >>> 5;
    for (i = 0; i < chunkIntLen; i += variantBlockIntInc) {
      if (updateProcessedLen + this.variantBlockSize <= chunkBinLen) {
        this.intermediateState = this.roundFunc(chunk.slice(i, i + variantBlockIntInc), this.intermediateState);
        updateProcessedLen += this.variantBlockSize;
      }
    }
    this.processedLen += updateProcessedLen;
    this.remainder = chunk.slice(updateProcessedLen >>> 5);
    this.remainderLen = chunkBinLen % this.variantBlockSize;
    this.updatedCalled = true;
  }

  /**
   * Returns the desired SHA hash of the string specified at instantiation
   * using the specified parameters
   *
   * @param format The desired output formatting (B64, HEX,
   *   BYTES, ARRAYBUFFER, or UINT8ARRAY)
   * @param options Hash list of output formatting options
   * @return The string representation of the hash
   *   in the format specified.
   */
  getHash(
    format: "B64" | "HEX" | "BYTES" | "ARRAYBUFFER" | "UINT8ARRAY",
    options?: { outputUpper?: boolean; b64Pad?: string; shakeLen?: number }
  ): string | ArrayBuffer | Uint8Array {
    let formatFunc, i, outputOptions: { outputUpper: boolean; b64Pad: string; shakeLen: number }, finalizedState;

    if (true === this.hmacKeySet) {
      throw new Error("Cannot call getHash after setting HMAC key");
    }

    outputOptions = getOutputOpts(options);
    formatFunc = getOutputConverter(format, this.outputBinLen, this.bigEndianMod, outputOptions);

    finalizedState = this.finalizeFunc(
      this.remainder.slice(),
      this.remainderLen,
      this.processedLen,
      this.stateCloneFunc(this.intermediateState),
      this.outputBinLen
    );
    for (i = 1; i < this.numRounds; i += 1) {
      finalizedState = this.finalizeFunc(
        finalizedState,
        this.outputBinLen,
        0,
        this.newStateFunc(this.shaVariant),
        this.outputBinLen
      );
    }

    return formatFunc(finalizedState);
  }

  /**
   * Sets the HMAC key for an eventual getHMAC call.  Must be called
   * immediately after jsSHA object instantiation
   *
   * @param key The key used to calculate the HMAC
   * @param inputFormat The format of key, HEX, TEXT, B64, BYTES,
   *   ARRAYBUFFER, or UINT8ARRAY
   * @param options Associative array
   *   of input format options
   */
  setHMACKey(
    key: string | ArrayBuffer | Uint8Array,
    inputFormat: "B64" | "HEX" | "BYTES" | "ARRAYBUFFER" | "UINT8ARRAY",
    options?: { encoding?: "UTF8" | "UTF16BE" | "UTF16LE" }
  ) {
    let keyConverterFunc,
      convertRet,
      keyBinLen,
      keyToUse,
      blockByteSize,
      i,
      lastArrayIndex,
      keyOptions,
      utfType: "UTF8" | "UTF16BE" | "UTF16LE";

    if (true === this.hmacKeySet) {
      throw new Error("HMAC key already set");
    }

    if (true === this.updatedCalled) {
      throw new Error("Cannot set HMAC key after calling update");
    }

    keyOptions = options || {};
    utfType = keyOptions["encoding"] || "UTF8";

    keyConverterFunc = getStrConverter(inputFormat, utfType, this.bigEndianMod);

    convertRet = keyConverterFunc(key);
    keyBinLen = convertRet["binLen"];
    keyToUse = convertRet["value"];

    blockByteSize = this.variantBlockSize >>> 3;

    /* These are used multiple times, calculate and store them */
    lastArrayIndex = blockByteSize / 4 - 1;

    /* Figure out what to do with the key based on its size relative to
     * the hash's block size */
    if (blockByteSize < keyBinLen / 8) {
      keyToUse = this.finalizeFunc(keyToUse, keyBinLen, 0, this.newStateFunc(this.shaVariant), this.outputBinLen);
      /* For all variants, the block size is bigger than the output
       * size so there will never be a useful byte at the end of the
       * string */
      while (keyToUse.length <= lastArrayIndex) {
        keyToUse.push(0);
      }
      keyToUse[lastArrayIndex] &= 0xffffff00;
    } else if (blockByteSize > keyBinLen / 8) {
      /* If the blockByteSize is greater than the key length, there
       * will always be at LEAST one "useless" byte at the end of the
       * string */
      while (keyToUse.length <= lastArrayIndex) {
        keyToUse.push(0);
      }
      keyToUse[lastArrayIndex] &= 0xffffff00;
    }

    /* Create ipad and opad */
    for (i = 0; i <= lastArrayIndex; i += 1) {
      this.keyWithIPad[i] = keyToUse[i] ^ 0x36363636;
      this.keyWithOPad[i] = keyToUse[i] ^ 0x5c5c5c5c;
    }

    this.intermediateState = this.roundFunc(this.keyWithIPad, this.intermediateState);
    this.processedLen = this.variantBlockSize;

    this.hmacKeySet = true;
  }

  /**
 * Returns the the HMAC in the specified format using the key given by
 * a previous setHMACKey call.
 *
 * @param format The desired output formatting
 *   (B64, HEX, BYTES, ARRAYBUFFER, or UINT8ARRAY)
 * @param options associative array of output
  *   formatting options
  * @return The string representation of the hash in the
  *   format specified.
  */
  getHMAC(format: "B64" | "HEX" | "BYTES" | "ARRAYBUFFER" | "UINT8ARRAY", options?: { outputUpper?: boolean, b64Pad?: string, shakeLen?: number }): string | ArrayBuffer | Uint8Array {
    let formatFunc, firstHash, outputOptions, finalizedState;

    if (false === this.hmacKeySet) {
      throw new Error("Cannot call getHMAC without first setting HMAC key");
    }

    outputOptions = getOutputOpts(options);
    formatFunc = getOutputConverter(format, this.outputBinLen, this.bigEndianMod, outputOptions);

    firstHash = this.finalizeFunc(this.remainder.slice(), this.remainderLen, this.processedLen, this.stateCloneFunc(this.intermediateState), this.outputBinLen);
    finalizedState = this.roundFunc(this.keyWithOPad, this.newStateFunc(this.shaVariant));
    finalizedState = this.finalizeFunc(firstHash, this.outputBinLen, this.variantBlockSize, finalizedState, this.outputBinLen);

    return formatFunc(finalizedState);
  };

}
