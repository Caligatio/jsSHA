import { sha_variant_error } from "./common";
import jsSHA1 from "./sha1";
import jsSHA256 from "./sha256";
import jsSHA512 from "./sha512";
import jsSHA3 from "./sha3";

export default class jsSHA {
  shaObj: jsSHA1 | jsSHA256 | jsSHA512 | jsSHA3;
  constructor(
    variant:
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
      | "SHAKE256",
    inputFormat: "HEX" | "TEXT" | "B64" | "BYTES" | "ARRAYBUFFER" | "UINT8ARRAY",
    options?: { encoding?: "UTF8" | "UTF16BE" | "UTF16LE"; numRounds?: number }
  ) {
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
  update(srcString: string | ArrayBuffer | Uint8Array) {
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
  getHash(
    format: "B64" | "HEX" | "BYTES" | "ARRAYBUFFER" | "UINT8ARRAY",
    options?: { outputUpper?: boolean; b64Pad?: string; shakeLen?: number }
  ): string | ArrayBuffer | Uint8Array {
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
  setHMACKey(
    key: string | ArrayBuffer | Uint8Array,
    inputFormat: "B64" | "HEX" | "BYTES" | "ARRAYBUFFER" | "UINT8ARRAY",
    options?: { encoding?: "UTF8" | "UTF16BE" | "UTF16LE" }
  ) {
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
  getHMAC(
    format: "B64" | "HEX" | "BYTES" | "ARRAYBUFFER" | "UINT8ARRAY",
    options?: { outputUpper?: boolean; b64Pad?: string; shakeLen?: number }
  ): string | ArrayBuffer | Uint8Array {
    return this.shaObj.getHMAC(format, options);
  }
}
