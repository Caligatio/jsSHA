declare type EncodingType = "UTF8" | "UTF16BE" | "UTF16LE";
declare type InputOptionsEncodingType = {
    encoding?: EncodingType;
    numRounds?: number;
};
declare type InputOptionsNoEncodingType = {
    numRounds?: number;
};
declare type FormatNoTextType = "HEX" | "B64" | "BYTES" | "ARRAYBUFFER" | "UINT8ARRAY";

declare type VariantType = "SHA-1" | "SHA-224" | "SHA-256" | "SHA-384" | "SHA-512" | "SHA3-224" | "SHA3-256" | "SHA3-384" | "SHA3-512" | "SHAKE128" | "SHAKE256";
declare class jsSHA {
    /**
     * @param variant The desired SHA variant (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-224, SHA3-256, SHA3-256,
     *   SHA3-384, SHA3-512, SHAKE128, or SHAKE256) as a string.
     * @param inputFormat The input format to be used in future `update` calls (TEXT, HEX, B64, BYTES, ARRAYBUFFER,
     *   or UINT8ARRAY) as a string.
     * @param options Optional extra options in the form of { encoding?: "UTF8" | "UTF16BE" | "UTF16LE";
     *   numRounds?: number }.  `encoding` is for only TEXT input (defaults to UTF8) and `numRounds` defaults to 1.
     */
    private readonly shaObj;
    constructor(variant: VariantType, inputFormat: "TEXT", options?: InputOptionsEncodingType);
    constructor(variant: VariantType, inputFormat: FormatNoTextType, options?: InputOptionsNoEncodingType);
    /**
     * Takes `input` and hashes as many blocks as possible. Stores the rest for either a future update or getHash call.
     *
     * @param input The input to be hashed
     */
    update(input: string | ArrayBuffer | Uint8Array): void;
    /**
     * Returns the desired SHA hash of the input fed in via `update` calls.
     *
     * @param format The desired output formatting (B64, HEX, BYTES, ARRAYBUFFER, or UINT8ARRAY) as a string.
     * @param options Options in the form of { outputUpper?: boolean; shakeLen?: number; b64Pad?: string }.  `shakeLen`
     *   is required for SHAKE128 and SHAKE256 variants.  `outputUpper` is only for HEX output (defaults to false) and
     *   b64pad is only for B64 output (defaults to "=").
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
     * @param inputFormat The format of key (HEX, TEXT, B64, BYTES, ARRAYBUFFER, or UINT8ARRAY) as a string.
     * @param options Options in the form of { encoding?: "UTF8" | "UTF16BE" | "UTF16LE }.  `encoding` is only for TEXT
     *   and defaults to UTF8.
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
     * @param format The desired output formatting (B64, HEX, BYTES, ARRAYBUFFER, or UINT8ARRAY) as a string.
     * @param options Options in the form of { outputUpper?: boolean; shakeLen?: number; b64Pad?: string }.  `shakeLen`
     *   is required for SHAKE128 and SHAKE256 variants.  `outputUpper` is only for HEX output (defaults to false) and
     *   b64pad is only for B64 output (defaults to "=").
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

export default jsSHA;
