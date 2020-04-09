/**
 * Return type for all the *2packed functions
 */
interface packedValue {
    value: number[];
    binLen: number;
}

declare type EncodingType = "UTF8" | "UTF16BE" | "UTF16LE";
declare type InputOptionsEncodingType = {
    encoding?: EncodingType;
    numRounds?: number;
};
declare type InputOptionsNoEncodingType = {
    numRounds?: number;
};
declare type FormatNoTextType = "HEX" | "B64" | "BYTES" | "ARRAYBUFFER" | "UINT8ARRAY";
declare abstract class jsSHABase<StateT, VariantT> {
    /**
     * @param variant The desired SHA variant.
     * @param inputFormat The input format to be used in future `update` calls.
     * @param options Hashmap of extra input options.
     */
    protected readonly shaVariant: VariantT;
    protected readonly inputFormat: FormatNoTextType | "TEXT";
    protected readonly utfType: EncodingType;
    protected readonly numRounds: number;
    protected abstract intermediateState: StateT;
    protected keyWithIPad: number[];
    protected keyWithOPad: number[];
    protected remainder: number[];
    protected remainderLen: number;
    protected updateCalled: boolean;
    protected processedLen: number;
    protected hmacKeySet: boolean;
    protected abstract readonly variantBlockSize: number;
    protected abstract readonly bigEndianMod: -1 | 1;
    protected abstract readonly outputBinLen: number;
    protected abstract readonly isSHAKE: boolean;
    protected abstract readonly converterFunc: (input: any, existingBin: number[], existingBinLen: number) => packedValue;
    protected abstract readonly roundFunc: (block: number[], H: StateT) => StateT;
    protected abstract readonly finalizeFunc: (remainder: number[], remainderBinLen: number, processedBinLen: number, H: StateT, outputLen: number) => number[];
    protected abstract readonly stateCloneFunc: (state: StateT) => StateT;
    protected abstract readonly newStateFunc: (variant: VariantT) => StateT;
    constructor(variant: VariantT, inputFormat: "TEXT", options?: InputOptionsEncodingType);
    constructor(variant: VariantT, inputFormat: FormatNoTextType, options?: InputOptionsNoEncodingType);
    /**
     * Hashes as many blocks as possible.  Stores the rest for either a future update or getHash call.
     *
     * @param srcString The string to be hashed.
     */
    update(srcString: string | ArrayBuffer | Uint8Array): void;
    /**
     * Returns the desired SHA hash of the input fed in via `update` calls.
     *
     * @param format The desired output formatting
     * @param options Hashmap of output formatting options
     * @returns The hash in the format specified.
     */
    getHash(format: "HEX", options?: {
        outputUpper?: boolean;
        shakeLen?: number;
    }): string;
    getHash(format: "B64", options?: {
        b64Pad?: string;
        shakeLen?: number;
    }): string;
    getHash(format: "BYTES", options?: {
        shakeLen?: number;
    }): string;
    getHash(format: "UINT8ARRAY", options?: {
        shakeLen?: number;
    }): Uint8Array;
    getHash(format: "ARRAYBUFFER", options?: {
        shakeLen?: number;
    }): ArrayBuffer;
    /**
     * Sets the HMAC key for an eventual `getHMAC` call.  Must be called immediately after jsSHA object instantiation.
     *
     * @param key The key used to calculate the HMAC
     * @param inputFormat The format of key.
     * @param options Hashmap of extra input options.
     */
    setHMACKey(key: string, inputFormat: "TEXT", options?: {
        encoding?: EncodingType;
    }): void;
    setHMACKey(key: string, inputFormat: "B64" | "HEX" | "BYTES"): void;
    setHMACKey(key: ArrayBuffer, inputFormat: "ARRAYBUFFER"): void;
    setHMACKey(key: Uint8Array, inputFormat: "UINT8ARRAY"): void;
    /**
     * Returns the the HMAC in the specified format using the key given by a previous `setHMACKey` call.
     *
     * @param format The desired output formatting.
     * @param options Hashmap of extra outputs options. `shakeLen` must be specified for SHAKE variants.
     * @returns The HMAC in the format specified.
     */
    getHMAC(format: "HEX", options?: {
        outputUpper?: boolean;
        shakeLen?: number;
    }): string;
    getHMAC(format: "B64", options?: {
        b64Pad?: string;
        shakeLen?: number;
    }): string;
    getHMAC(format: "BYTES", options?: {
        shakeLen?: number;
    }): string;
    getHMAC(format: "UINT8ARRAY", options?: {
        shakeLen?: number;
    }): Uint8Array;
    getHMAC(format: "ARRAYBUFFER", options?: {
        shakeLen?: number;
    }): ArrayBuffer;
}

/**
 * Note 1: All the functions in this file guarantee only that the bottom 32-bits of the returned Int_64 are correct.
 * JavaScript is flakey when it comes to bit operations and a '1' in the highest order bit of a 32-bit number causes
 * it to be interpreted as a negative number per two's complement.
 *
 * Note 2: Per the ECMAScript spec, all JavaScript operations mask the shift amount by 0x1F.  This results in weird
 * cases like 1 << 32 == 1 and 1 << 33 === 1 << 1 === 2
 */
/**
 * Int_64 is a object for 2 32-bit numbers emulating a 64-bit number.
 */
declare class Int_64 {
    /**
     * @param msint_32 The most significant 32-bits of a 64-bit number.
     * @param lsint_32 The least significant 32-bits of a 64-bit number.
     */
    readonly highOrder: number;
    readonly lowOrder: number;
    constructor(msint_32: number, lsint_32: number);
}

declare type VariantType = "SHA3-224" | "SHA3-256" | "SHA3-384" | "SHA3-512" | "SHAKE128" | "SHAKE256";
declare class jsSHA extends jsSHABase<Int_64[][], VariantType> {
    intermediateState: Int_64[][];
    variantBlockSize: number;
    bigEndianMod: -1 | 1;
    outputBinLen: number;
    isSHAKE: boolean;
    converterFunc: (input: any, existingBin: number[], existingBinLen: number) => packedValue;
    roundFunc: (block: number[], H: Int_64[][]) => Int_64[][];
    finalizeFunc: (remainder: number[], remainderBinLen: number, processedBinLen: number, H: Int_64[][], outputLen: number) => number[];
    stateCloneFunc: (state: Int_64[][]) => Int_64[][];
    newStateFunc: (variant: VariantType) => Int_64[][];
    constructor(variant: VariantType, inputFormat: "TEXT", options?: InputOptionsEncodingType);
    constructor(variant: VariantType, inputFormat: FormatNoTextType, options?: InputOptionsNoEncodingType);
}

export default jsSHA;
