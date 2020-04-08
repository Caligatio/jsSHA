import {
  EncodingType,
  InputOptionsEncodingType,
  InputOptionsNoEncodingType,
  FormatNoTextType,
  sha_variant_error,
} from "./common";
import jsSHA1 from "./sha1";
import jsSHA256 from "./sha256";
import jsSHA512 from "./sha512";
import jsSHA3 from "./sha3";

type VariantType =
  | "SHA-1"
  | "SHA-224"
  | "SHA-256"
  | "SHA-384"
  | "SHA-512"
  | "SHA3-224"
  | "SHA3-256"
  | "SHA3-384"
  | "SHA3-512"
  | "SHAKE128"
  | "SHAKE256";

export default class jsSHA {
  protected readonly shaObj: jsSHA1 | jsSHA256 | jsSHA512 | jsSHA3;
  constructor(variant: VariantType, inputFormat: "TEXT", options?: InputOptionsEncodingType);
  constructor(variant: VariantType, inputFormat: FormatNoTextType, options?: InputOptionsNoEncodingType);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  constructor(variant: any, inputFormat: any, options?: any) {
    if ("SHA-1" == variant) {
      this.shaObj = new jsSHA1(variant, inputFormat, options);
    } else if ("SHA-224" == variant || "SHA-256" == variant) {
      this.shaObj = new jsSHA256(variant, inputFormat, options);
    } else if ("SHA-384" == variant || "SHA-512" == variant) {
      this.shaObj = new jsSHA512(variant, inputFormat, options);
    } else if (
      "SHA3-224" == variant ||
      "SHA3-256" == variant ||
      "SHA3-384" == variant ||
      "SHA3-512" == variant ||
      "SHAKE128" == variant ||
      "SHAKE256" == variant
    ) {
      this.shaObj = new jsSHA3(variant, inputFormat, options);
    } else {
      throw new Error(sha_variant_error);
    }
  }

  /**
   * Takes strString and hashes as many blocks as possible.  Stores the
   * rest for either a future update or getHash call.
   *
   * @param srcString The string to be hashed
   */
  update(srcString: string | ArrayBuffer | Uint8Array): void {
    this.shaObj.update(srcString);
  }

  /**
   * Returns the desired SHA hash of the string specified at instantiation
   * using the specified parameters
   *
   * @param format The desired output formatting (B64, HEX,
   *   BYTES, ARRAYBUFFER, or UINT8ARRAY)
   * @param options Hash list of output formatting options
   * @returns The string representation of the hash
   *   in the format specified.
   */
  getHash(format: "HEX", options?: { outputUpper?: boolean; shakeLen?: number }): string;
  getHash(format: "B64", options?: { b64Pad?: string; shakeLen?: number }): string;
  getHash(format: "BYTES", options?: { shakeLen?: number }): string;
  getHash(format: "UINT8ARRAY", options?: { shakeLen?: number }): Uint8Array;
  getHash(format: "ARRAYBUFFER", options?: { shakeLen?: number }): ArrayBuffer;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  getHash(format: any, options?: any): any {
    return this.shaObj.getHash(format, options);
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
  setHMACKey(key: string, inputFormat: "TEXT", options?: { encoding?: EncodingType }): void;
  setHMACKey(key: string, inputFormat: "B64" | "HEX" | "BYTES"): void;
  setHMACKey(key: ArrayBuffer, inputFormat: "ARRAYBUFFER"): void;
  setHMACKey(key: Uint8Array, inputFormat: "UINT8ARRAY"): void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  setHMACKey(key: any, inputFormat: any, options?: any): void {
    this.shaObj.setHMACKey(key, inputFormat, options);
  }

  /**
   * Returns the the HMAC in the specified format using the key given by
   * a previous setHMACKey call.
   *
   * @param format The desired output formatting
   *   (B64, HEX, BYTES, ARRAYBUFFER, or UINT8ARRAY)
   * @param options associative array of output
   *   formatting options
   * @returns The string representation of the hash in the
   *   format specified.
   */
  getHMAC(format: "HEX", options?: { outputUpper?: boolean; shakeLen?: number }): string;
  getHMAC(format: "B64", options?: { b64Pad?: string; shakeLen?: number }): string;
  getHMAC(format: "BYTES", options?: { shakeLen?: number }): string;
  getHMAC(format: "UINT8ARRAY", options?: { shakeLen?: number }): Uint8Array;
  getHMAC(format: "ARRAYBUFFER", options?: { shakeLen?: number }): ArrayBuffer;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  getHMAC(format: any, options?: any): any {
    return this.shaObj.getHMAC(format, options);
  }
}
