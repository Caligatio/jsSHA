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

declare type VariantType = "SHA-224" | "SHA-256";
declare class jsSHA extends jsSHABase<number[], VariantType> {
    intermediateState: number[];
    variantBlockSize: number;
    bigEndianMod: -1 | 1;
    outputBinLen: number;
    isSHAKE: boolean;
    converterFunc: (input: any, existingBin: number[], existingBinLen: number) => packedValue;
    roundFunc: (block: number[], H: number[]) => number[];
    finalizeFunc: (remainder: number[], remainderBinLen: number, processedBinLen: number, H: number[]) => number[];
    stateCloneFunc: (state: number[]) => number[];
    newStateFunc: (variant: VariantType) => number[];
    constructor(variant: VariantType, inputFormat: "TEXT", options?: InputOptionsEncodingType);
    constructor(variant: VariantType, inputFormat: FormatNoTextType, options?: InputOptionsNoEncodingType);
}

export default jsSHA;
