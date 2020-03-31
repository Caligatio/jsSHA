import { getOutputOpts, TWO_PWR_32 } from "./common";
import { packedValue, getStrConverter, getOutputConverter } from "./converters";
import { ch_32, parity_32, maj_32, rotl_32, safeAdd_32_2, safeAdd_32_5 } from "./primitives_32";

/**
 * Gets the state values for the specified SHA variant
 *
 * @returns The initial state values
 */
function getNewState(_variant: "SHA-1"): number[] {
  return [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
}

/**
 * Performs a round of SHA-1 hashing over a 512-byte block
 *
 * @private
 * @param block The binary array representation of the
 *   block to hash
 * @param H The intermediate H values from a previous
 *   round
 * @return The resulting H values
 */
function roundSHA1(block: number[], H: number[]): number[] {
  let W: number[] = [],
    a,
    b,
    c,
    d,
    e,
    T,
    ch = ch_32,
    parity = parity_32,
    maj = maj_32,
    rotl = rotl_32,
    safeAdd_2 = safeAdd_32_2,
    t,
    safeAdd_5 = safeAdd_32_5;

  a = H[0];
  b = H[1];
  c = H[2];
  d = H[3];
  e = H[4];

  for (t = 0; t < 80; t += 1) {
    if (t < 16) {
      W[t] = block[t];
    } else {
      W[t] = rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    }

    if (t < 20) {
      T = safeAdd_5(rotl(a, 5), ch(b, c, d), e, 0x5a827999, W[t]);
    } else if (t < 40) {
      T = safeAdd_5(rotl(a, 5), parity(b, c, d), e, 0x6ed9eba1, W[t]);
    } else if (t < 60) {
      T = safeAdd_5(rotl(a, 5), maj(b, c, d), e, 0x8f1bbcdc, W[t]);
    } else {
      T = safeAdd_5(rotl(a, 5), parity(b, c, d), e, 0xca62c1d6, W[t]);
    }

    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = T;
  }

  H[0] = safeAdd_2(a, H[0]);
  H[1] = safeAdd_2(b, H[1]);
  H[2] = safeAdd_2(c, H[2]);
  H[3] = safeAdd_2(d, H[3]);
  H[4] = safeAdd_2(e, H[4]);

  return H;
}

/**
 * Finalizes the SHA-1 hash
 *
 * @param remainder Any leftover unprocessed packed ints
 *   that still need to be processed
 * @param remainderBinLen The number of bits in remainder
 * @param processedBinLen The number of bits already
 *   processed
 * @param H The intermediate H values from a previous
 *   round
 * @param outputLen Unused for this variant
 * @return The array of integers representing the SHA-1
 *   hash of message
 */
function finalizeSHA1(
  remainder: number[],
  remainderBinLen: number,
  processedBinLen: number,
  H: number[],
  _outputLen: number
): number[] {
  let i: number, appendedMessageLength: number, offset: number, totalLen: number;

  /* The 65 addition is a hack but it works.  The correct number is
		actually 72 (64 + 8) but the below math fails if
		remainderBinLen + 72 % 512 = 0. Since remainderBinLen % 8 = 0,
		"shorting" the addition is OK. */
  offset = (((remainderBinLen + 65) >>> 9) << 4) + 15;
  while (remainder.length <= offset) {
    remainder.push(0);
  }
  /* Append '1' at the end of the binary string */
  remainder[remainderBinLen >>> 5] |= 0x80 << (24 - (remainderBinLen % 32));
  /* Append length of binary string in the position such that the new
   * length is a multiple of 512.  Logic does not work for even multiples
   * of 512 but there can never be even multiples of 512. JavaScript
   * numbers are limited to 2^53 so it's "safe" to treat the totalLen as
   * a 64-bit integer. */
  totalLen = remainderBinLen + processedBinLen;
  remainder[offset] = totalLen & 0xffffffff;
  /* Bitwise operators treat the operand as a 32-bit number so need to
   * use hacky division and round to get access to upper 32-ish bits */
  remainder[offset - 1] = (totalLen / TWO_PWR_32) | 0;

  appendedMessageLength = remainder.length;

  /* This will always be at least 1 full chunk */
  for (i = 0; i < appendedMessageLength; i += 16) {
    H = roundSHA1(remainder.slice(i, i + 16), H);
  }

  return H;
}

export default class jsSHA {
  shaVariant: "SHA-1";
  inputOptions: { encoding?: "UTF8" | "UTF16BE" | "UTF16LE"; numRounds?: number };
  utfType: "UTF8" | "UTF16BE" | "UTF16LE";
  numRounds: number;
  intermediateState: number[];
  keyWithIPad: number[];
  keyWithOPad: number[];
  converterFunc: (input: any, existingBin: number[], existingBinLen: number) => packedValue;
  remainder: number[];
  remainderLen: number;
  variantBlockSize: number;
  updatedCalled: boolean;
  processedLen: number;
  roundFunc: (block: number[], H: number[]) => number[];
  finalizeFunc: (
    remainder: number[],
    remainderBinLen: number,
    processedBinLen: number,
    H: number[],
    _outputLen: number
  ) => number[];
  stateCloneFunc: (state: number[]) => number[];
  outputBinLen: number;
  bigEndianMod: -1 | 1;
  hmacKeySet: boolean;

  constructor(
    variant: "SHA-1",
    inputFormat: "HEX" | "TEXT" | "B64" | "BYTES" | "ARRAYBUFFER" | "UINT8ARRAY",
    options?: { encoding?: "UTF8" | "UTF16BE" | "UTF16LE"; numRounds?: number }
  ) {
    this.inputOptions = options || {};
    this.utfType = this.inputOptions["encoding"] || "UTF8";
    this.numRounds = this.inputOptions["numRounds"] || 1;

    if ("SHA-1" !== variant) {
      throw new Error("Chosen SHA variant is not supported");
    }

    // @ts-ignore - Need to use parseInt as a type-check
    if (this.numRounds !== parseInt(this.numRounds, 10) || 1 > this.numRounds) {
      throw new Error("numRounds must a integer >= 1");
    }

    this.shaVariant = variant;
    this.intermediateState = getNewState(variant);
    this.converterFunc = getStrConverter(inputFormat, this.utfType, -1);
    this.remainder = [];
    this.remainderLen = 0;
    this.variantBlockSize = 512;
    this.updatedCalled = false;
    this.processedLen = 0;
    this.roundFunc = roundSHA1;
    this.stateCloneFunc = function (state: number[]): number[] {
      return state.slice();
    };
    this.finalizeFunc = finalizeSHA1;
    this.outputBinLen = 160;
    this.bigEndianMod = -1;
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
   * @return {string|ArrayBuffer|Uint8Array} The string representation of the hash
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
        getNewState(this.shaVariant),
        this.outputBinLen
      );
    }

    return formatFunc(finalizedState);
  }

  /**
   * Sets the HMAC key for an eventual getHMAC call.  Must be called
   * immediately after jsSHA object instantiation
   *
   * @expose
   * @param {string|ArrayBuffer|Uint8Array} key The key used to calculate the HMAC
   * @param {string} inputFormat The format of key, HEX, TEXT, B64, BYTES,
   *   ARRAYBUFFER, or UINT8ARRAY
   * @param {{encoding : (string|undefined)}=} options Associative array
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
      keyToUse = this.finalizeFunc(keyToUse, keyBinLen, 0, getNewState(this.shaVariant), this.outputBinLen);
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
 * @param {string} format The desired output formatting
 *   (B64, HEX, BYTES, ARRAYBUFFER, or UINT8ARRAY)
 * @param {{outputUpper : (boolean|undefined), b64Pad : (string|undefined),
  *   shakeLen : (number|undefined)}=} options associative array of output
  *   formatting options
  * @return {string|ArrayBuffer|Uint8Array} The string representation of the hash in the
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
    finalizedState = this.roundFunc(this.keyWithOPad, getNewState(this.shaVariant));
    finalizedState = this.finalizeFunc(firstHash, this.outputBinLen, this.variantBlockSize, finalizedState, this.outputBinLen);

    return formatFunc(finalizedState);
  };

}
