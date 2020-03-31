export const TWO_PWR_32 = 4294967296;


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
