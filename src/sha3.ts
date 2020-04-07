import {
  InputOptionsEncodingType,
  InputOptionsNoEncodingType,
  FormatNoTextType,
  jsSHABase,
  sha_variant_error,
} from "./common";
import { packedValue, getStrConverter } from "./converters";
import { Int_64, rotl_64, xor_64_2, xor_64_5 } from "./primitives_64";

type VariantType = "SHA3-224" | "SHA3-256" | "SHA3-384" | "SHA3-512" | "SHAKE128" | "SHAKE256";

const rc_sha3 = [
  new Int_64(0x00000000, 0x00000001),
  new Int_64(0x00000000, 0x00008082),
  new Int_64(0x80000000, 0x0000808a),
  new Int_64(0x80000000, 0x80008000),
  new Int_64(0x00000000, 0x0000808b),
  new Int_64(0x00000000, 0x80000001),
  new Int_64(0x80000000, 0x80008081),
  new Int_64(0x80000000, 0x00008009),
  new Int_64(0x00000000, 0x0000008a),
  new Int_64(0x00000000, 0x00000088),
  new Int_64(0x00000000, 0x80008009),
  new Int_64(0x00000000, 0x8000000a),
  new Int_64(0x00000000, 0x8000808b),
  new Int_64(0x80000000, 0x0000008b),
  new Int_64(0x80000000, 0x00008089),
  new Int_64(0x80000000, 0x00008003),
  new Int_64(0x80000000, 0x00008002),
  new Int_64(0x80000000, 0x00000080),
  new Int_64(0x00000000, 0x0000800a),
  new Int_64(0x80000000, 0x8000000a),
  new Int_64(0x80000000, 0x80008081),
  new Int_64(0x80000000, 0x00008080),
  new Int_64(0x00000000, 0x80000001),
  new Int_64(0x80000000, 0x80008008),
];

const r_sha3 = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];

/**
 * Gets the state values for the specified SHA-3 variant
 *
 * @param variant The SHA-3 family variant
 * @returns The initial state values
 */
function getNewState(_variant: VariantType): Int_64[][] {
  let i;
  const retVal = [];

  for (i = 0; i < 5; i += 1) {
    retVal[i] = [new Int_64(0, 0), new Int_64(0, 0), new Int_64(0, 0), new Int_64(0, 0), new Int_64(0, 0)];
  }

  return retVal;
}

/**
 * Returns a clone of the given SHA3 state
 *
 * @param state The state to be cloned
 * @returns The cloned state
 */
function cloneSHA3State(state: Int_64[][]): Int_64[][] {
  let i;
  const clone = [];
  for (i = 0; i < 5; i += 1) {
    clone[i] = state[i].slice();
  }

  return clone;
}

/**
 * Performs a round of SHA-3 hashing over a block
 *
 * @param block The binary array representation of the
 *   block to hash
 * @param state The binary array representation of the
 *   block to hash
 * @returns The resulting state value
 */
function roundSHA3(block: number[] | null, state: Int_64[][]): Int_64[][] {
  let round, x, y, B;
  const C = [],
    D = [];

  if (null !== block) {
    for (x = 0; x < block.length; x += 2) {
      state[(x >>> 1) % 5][((x >>> 1) / 5) | 0] = xor_64_2(
        state[(x >>> 1) % 5][((x >>> 1) / 5) | 0],
        new Int_64(block[x + 1], block[x])
      );
    }
  }

  for (round = 0; round < 24; round += 1) {
    /* Any SHA-3 variant name will do here */
    B = getNewState("SHA3-384");

    /* Perform theta step */
    for (x = 0; x < 5; x += 1) {
      C[x] = xor_64_5(state[x][0], state[x][1], state[x][2], state[x][3], state[x][4]);
    }
    for (x = 0; x < 5; x += 1) {
      D[x] = xor_64_2(C[(x + 4) % 5], rotl_64(C[(x + 1) % 5], 1));
    }
    for (x = 0; x < 5; x += 1) {
      for (y = 0; y < 5; y += 1) {
        state[x][y] = xor_64_2(state[x][y], D[x]);
      }
    }

    /* Perform combined ro and pi steps */
    for (x = 0; x < 5; x += 1) {
      for (y = 0; y < 5; y += 1) {
        B[y][(2 * x + 3 * y) % 5] = rotl_64(state[x][y], r_sha3[x][y]);
      }
    }

    /* Perform chi step */
    for (x = 0; x < 5; x += 1) {
      for (y = 0; y < 5; y += 1) {
        state[x][y] = xor_64_2(
          B[x][y],
          new Int_64(
            ~B[(x + 1) % 5][y].highOrder & B[(x + 2) % 5][y].highOrder,
            ~B[(x + 1) % 5][y].lowOrder & B[(x + 2) % 5][y].lowOrder
          )
        );
      }
    }

    /* Perform iota step */
    state[0][0] = xor_64_2(state[0][0], rc_sha3[round]);
  }

  return state;
}

/**
 * Finalizes the SHA-3 hash
 *
 * @param remainder Any leftover unprocessed packed ints
 *   that still need to be processed
 * @param remainderBinLen The number of bits in remainder
 * @param processedBinLen The number of bits already
 *   processed
 * @param state The state from a previous round
 * @param blockSize The block size/rate of the variant in bits
 * @param delimiter The delimiter value for the variant
 * @param outputLen The output length for the variant in bits
 * @returns The array of integers representing the SHA-3
 *   hash of message
 */
function finalizeSHA3(
  remainder: number[],
  remainderBinLen: number,
  _processedBinLen: number,
  state: Int_64[][],
  blockSize: number,
  delimiter: number,
  outputLen: number
): number[] {
  let i,
    state_offset = 0,
    temp;
  const retVal = [],
    binaryStringInc = blockSize >>> 5,
    remainderIntLen = remainderBinLen >>> 5;

  /* Process as many blocks as possible, some may be here for multiple rounds
		with SHAKE
	*/
  for (i = 0; i < remainderIntLen && remainderBinLen >= blockSize; i += binaryStringInc) {
    state = roundSHA3(remainder.slice(i, i + binaryStringInc), state);
    remainderBinLen -= blockSize;
  }

  remainder = remainder.slice(i);
  remainderBinLen = remainderBinLen % blockSize;

  /* Pad out the remainder to a full block */
  while (remainder.length < binaryStringInc) {
    remainder.push(0);
  }

  /* Find the next "empty" byte for the 0x80 and append it via an xor */
  i = remainderBinLen >>> 3;
  remainder[i >> 2] ^= delimiter << (8 * (i % 4));

  remainder[binaryStringInc - 1] ^= 0x80000000;
  state = roundSHA3(remainder, state);

  while (retVal.length * 32 < outputLen) {
    temp = state[state_offset % 5][(state_offset / 5) | 0];
    retVal.push(temp.lowOrder);
    if (retVal.length * 32 >= outputLen) {
      break;
    }
    retVal.push(temp.highOrder);
    state_offset += 1;

    if (0 === (state_offset * 64) % blockSize) {
      roundSHA3(null, state);
    }
  }

  return retVal;
}

export default class jsSHA extends jsSHABase<Int_64[][], VariantType> {
  intermediateState: Int_64[][];
  variantBlockSize: number;
  bigEndianMod: -1 | 1;
  outputBinLen: number;
  isSHAKE: boolean;

  /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
  converterFunc: (input: any, existingBin: number[], existingBinLen: number) => packedValue;
  roundFunc: (block: number[], H: Int_64[][]) => Int_64[][];
  finalizeFunc: (
    remainder: number[],
    remainderBinLen: number,
    processedBinLen: number,
    H: Int_64[][],
    outputLen: number
  ) => number[];
  stateCloneFunc: (state: Int_64[][]) => Int_64[][];
  newStateFunc: (variant: VariantType) => Int_64[][];

  constructor(variant: VariantType, inputFormat: "TEXT", options?: InputOptionsEncodingType);
  constructor(variant: VariantType, inputFormat: FormatNoTextType, options?: InputOptionsNoEncodingType);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  constructor(variant: any, inputFormat: any, options?: any) {
    let delimiter = 0x06,
      variantBlockSize = 0;
    super(variant, inputFormat, options);

    this.isSHAKE = false;
    if ("SHA3-224" === variant) {
      variantBlockSize = 1152;
      this.outputBinLen = 224;
    } else if ("SHA3-256" === variant) {
      variantBlockSize = 1088;
      this.outputBinLen = 256;
    } else if ("SHA3-384" === variant) {
      variantBlockSize = 832;
      this.outputBinLen = 384;
    } else if ("SHA3-512" === variant) {
      variantBlockSize = 576;
      this.outputBinLen = 512;
    } else if ("SHAKE128" === variant) {
      delimiter = 0x1f;
      variantBlockSize = 1344;
      /* This will be set in getHash */
      this.outputBinLen = -1;
      this.isSHAKE = true;
    } else if ("SHAKE256" === variant) {
      delimiter = 0x1f;
      variantBlockSize = 1088;
      /* This will be set in getHash */
      this.outputBinLen = -1;
      this.isSHAKE = true;
    } else {
      throw new Error(sha_variant_error);
    }

    this.variantBlockSize = variantBlockSize;

    this.bigEndianMod = 1;
    this.converterFunc = getStrConverter(this.inputFormat, this.utfType, this.bigEndianMod);
    this.roundFunc = roundSHA3;
    this.stateCloneFunc = cloneSHA3State;
    this.newStateFunc = getNewState;
    this.finalizeFunc = function (remainder, remainderBinLen, processedBinLen, state, outputBinLen): number[] {
      return finalizeSHA3(
        remainder,
        remainderBinLen,
        processedBinLen,
        state,
        variantBlockSize,
        delimiter,
        outputBinLen
      );
    };
    this.intermediateState = getNewState(variant);
  }
}
