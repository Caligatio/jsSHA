/**
 * Int_64 is a object for 2 32-bit numbers emulating a 64-bit number
 *
 * @param msint_32 The most significant 32-bits of a 64-bit number
 * @param lsint_32 The least significant 32-bits of a 64-bit number
 */
export class Int_64 {
  highOrder: number;
  lowOrder: number;
  constructor(msint_32: number, lsint_32: number) {
    this.highOrder = msint_32;
    this.lowOrder = lsint_32;
  }
}

/**
 * The 64-bit implementation of circular rotate left
 *
 * @param x The 64-bit integer argument
 * @param n The number of bits to shift
 * @returns The x shifted circularly by n bits
 */
export function rotl_64(x: Int_64, n: number): Int_64 {
  if (n > 32) {
    n = n - 32;
    return new Int_64((x.lowOrder << n) | (x.highOrder >>> (32 - n)), (x.highOrder << n) | (x.lowOrder >>> (32 - n)));
  } else if (0 !== n) {
    return new Int_64((x.highOrder << n) | (x.lowOrder >>> (32 - n)), (x.lowOrder << n) | (x.highOrder >>> (32 - n)));
  } else {
    return x;
  }
}

/**
 * The 64-bit implementation of circular rotate right
 *
 * @param x The 64-bit integer argument
 * @param n The number of bits to shift
 * @returns The x shifted circularly by n bits
 */
function rotr_64(x: Int_64, n: number): Int_64 {
  let retVal: Int_64;

  if (32 >= n) {
    retVal = new Int_64(
      (x.highOrder >>> n) | ((x.lowOrder << (32 - n)) & 0xffffffff),
      (x.lowOrder >>> n) | ((x.highOrder << (32 - n)) & 0xffffffff)
    );
  } else {
    retVal = new Int_64(
      (x.lowOrder >>> (n - 32)) | ((x.highOrder << (64 - n)) & 0xffffffff),
      (x.highOrder >>> (n - 32)) | ((x.lowOrder << (64 - n)) & 0xffffffff)
    );
  }

  return retVal;
}

/**
 * The 64-bit implementation of shift right
 *
 * @param x The 64-bit integer argument
 * @param n The number of bits to shift
 * @returns The x shifted by n bits
 */
function shr_64(x: Int_64, n: number): Int_64 {
  let retVal: Int_64;

  if (32 >= n) {
    retVal = new Int_64(x.highOrder >>> n, (x.lowOrder >>> n) | ((x.highOrder << (32 - n)) & 0xffffffff));
  } else {
    retVal = new Int_64(0, x.highOrder >>> (n - 32));
  }

  return retVal;
}

/**
 * The 64-bit implementation of the NIST specified Ch function
 *
 * @param x The first 64-bit integer argument
 * @param y The second 64-bit integer argument
 * @param z The third 64-bit integer argument
 * @returns The NIST specified output of the function
 */
export function ch_64(x: Int_64, y: Int_64, z: Int_64): Int_64 {
  return new Int_64(
    (x.highOrder & y.highOrder) ^ (~x.highOrder & z.highOrder),
    (x.lowOrder & y.lowOrder) ^ (~x.lowOrder & z.lowOrder)
  );
}

/**
 * The 64-bit implementation of the NIST specified Maj function
 *
 * @param x The first 64-bit integer argument
 * @param y The second 64-bit integer argument
 * @param z The third 64-bit integer argument
 * @returns The NIST specified output of the function
 */
export function maj_64(x: Int_64, y: Int_64, z: Int_64): Int_64 {
  return new Int_64(
    (x.highOrder & y.highOrder) ^ (x.highOrder & z.highOrder) ^ (y.highOrder & z.highOrder),
    (x.lowOrder & y.lowOrder) ^ (x.lowOrder & z.lowOrder) ^ (y.lowOrder & z.lowOrder)
  );
}

/**
 * The 64-bit implementation of the NIST specified Sigma0 function
 *
 * @param x The 64-bit integer argument
 * @returns The NIST specified output of the function
 */
export function sigma0_64(x: Int_64): Int_64 {
  const rotr28 = rotr_64(x, 28),
    rotr34 = rotr_64(x, 34),
    rotr39 = rotr_64(x, 39);

  return new Int_64(
    rotr28.highOrder ^ rotr34.highOrder ^ rotr39.highOrder,
    rotr28.lowOrder ^ rotr34.lowOrder ^ rotr39.lowOrder
  );
}

/**
 * Add two 64-bit integers, wrapping at 2^64. This uses 16-bit operations
 * internally to work around bugs in some JS interpreters.
 *
 * @param x The first 64-bit integer argument to be added
 * @param y The second 64-bit integer argument to be added
 * @returns The sum of x + y
 */
export function safeAdd_64_2(x: Int_64, y: Int_64): Int_64 {
  let lsw, msw;

  lsw = (x.lowOrder & 0xffff) + (y.lowOrder & 0xffff);
  msw = (x.lowOrder >>> 16) + (y.lowOrder >>> 16) + (lsw >>> 16);
  const lowOrder = ((msw & 0xffff) << 16) | (lsw & 0xffff);

  lsw = (x.highOrder & 0xffff) + (y.highOrder & 0xffff) + (msw >>> 16);
  msw = (x.highOrder >>> 16) + (y.highOrder >>> 16) + (lsw >>> 16);
  const highOrder = ((msw & 0xffff) << 16) | (lsw & 0xffff);

  return new Int_64(highOrder, lowOrder);
}

/**
 * Add four 64-bit integers, wrapping at 2^64. This uses 16-bit operations
 * internally to work around bugs in some JS interpreters.
 *
 * @param a The first 64-bit integer argument to be added
 * @param b The second 64-bit integer argument to be added
 * @param c The third 64-bit integer argument to be added
 * @param d The fouth 64-bit integer argument to be added
 * @returns The sum of a + b + c + d
 */
export function safeAdd_64_4(a: Int_64, b: Int_64, c: Int_64, d: Int_64): Int_64 {
  let lsw, msw;

  lsw = (a.lowOrder & 0xffff) + (b.lowOrder & 0xffff) + (c.lowOrder & 0xffff) + (d.lowOrder & 0xffff);
  msw = (a.lowOrder >>> 16) + (b.lowOrder >>> 16) + (c.lowOrder >>> 16) + (d.lowOrder >>> 16) + (lsw >>> 16);
  const lowOrder = ((msw & 0xffff) << 16) | (lsw & 0xffff);

  lsw =
    (a.highOrder & 0xffff) + (b.highOrder & 0xffff) + (c.highOrder & 0xffff) + (d.highOrder & 0xffff) + (msw >>> 16);
  msw = (a.highOrder >>> 16) + (b.highOrder >>> 16) + (c.highOrder >>> 16) + (d.highOrder >>> 16) + (lsw >>> 16);
  const highOrder = ((msw & 0xffff) << 16) | (lsw & 0xffff);

  return new Int_64(highOrder, lowOrder);
}

/**
 * Add five 64-bit integers, wrapping at 2^64. This uses 16-bit operations
 * internally to work around bugs in some JS interpreters.
 *
 * @param a The first 64-bit integer argument to be added
 * @param b The second 64-bit integer argument to be added
 * @param c The third 64-bit integer argument to be added
 * @param d The fouth 64-bit integer argument to be added
 * @param e The fouth 64-bit integer argument to be added
 * @returns The sum of a + b + c + d + e
 */
export function safeAdd_64_5(a: Int_64, b: Int_64, c: Int_64, d: Int_64, e: Int_64): Int_64 {
  let lsw, msw;

  lsw =
    (a.lowOrder & 0xffff) +
    (b.lowOrder & 0xffff) +
    (c.lowOrder & 0xffff) +
    (d.lowOrder & 0xffff) +
    (e.lowOrder & 0xffff);
  msw =
    (a.lowOrder >>> 16) +
    (b.lowOrder >>> 16) +
    (c.lowOrder >>> 16) +
    (d.lowOrder >>> 16) +
    (e.lowOrder >>> 16) +
    (lsw >>> 16);
  const lowOrder = ((msw & 0xffff) << 16) | (lsw & 0xffff);

  lsw =
    (a.highOrder & 0xffff) +
    (b.highOrder & 0xffff) +
    (c.highOrder & 0xffff) +
    (d.highOrder & 0xffff) +
    (e.highOrder & 0xffff) +
    (msw >>> 16);
  msw =
    (a.highOrder >>> 16) +
    (b.highOrder >>> 16) +
    (c.highOrder >>> 16) +
    (d.highOrder >>> 16) +
    (e.highOrder >>> 16) +
    (lsw >>> 16);
  const highOrder = ((msw & 0xffff) << 16) | (lsw & 0xffff);

  return new Int_64(highOrder, lowOrder);
}

/**
 * XORs two given arguments.
 *
 * @param a First argument to be XORed
 * @param b Second argument to be XORed
 * @returns The XOR of the arguments
 */
export function xor_64_2(a: Int_64, b: Int_64): Int_64 {
  return new Int_64(a.highOrder ^ b.highOrder, a.lowOrder ^ b.lowOrder);
}

/**
 * XORs five given arguments.
 *
 * @param a First argument to be XORed
 * @param b Second argument to be XORed
 * @param c Third argument to be XORed
 * @param d Fourth argument to be XORed
 * @param e Fifth argument to be XORed
 * @returns The XOR of the arguments
 */
export function xor_64_5(a: Int_64, b: Int_64, c: Int_64, d: Int_64, e: Int_64): Int_64 {
  return new Int_64(
    a.highOrder ^ b.highOrder ^ c.highOrder ^ d.highOrder ^ e.highOrder,
    a.lowOrder ^ b.lowOrder ^ c.lowOrder ^ d.lowOrder ^ e.lowOrder
  );
}

/**
 * The 64-bit implementation of the NIST specified Gamma1 function
 *
 * @param x The 64-bit integer argument
 * @returns The NIST specified output of the function
 */
export function gamma1_64(x: Int_64): Int_64 {
  const rotr19 = rotr_64(x, 19),
    rotr61 = rotr_64(x, 61),
    shr6 = shr_64(x, 6);

  return new Int_64(
    rotr19.highOrder ^ rotr61.highOrder ^ shr6.highOrder,
    rotr19.lowOrder ^ rotr61.lowOrder ^ shr6.lowOrder
  );
}

/**
 * The 64-bit implementation of the NIST specified Gamma0 function
 *
 * @param x The 64-bit integer argument
 * @returns The NIST specified output of the function
 */
export function gamma0_64(x: Int_64): Int_64 {
  const rotr1 = rotr_64(x, 1),
    rotr8 = rotr_64(x, 8),
    shr7 = shr_64(x, 7);

  return new Int_64(
    rotr1.highOrder ^ rotr8.highOrder ^ shr7.highOrder,
    rotr1.lowOrder ^ rotr8.lowOrder ^ shr7.lowOrder
  );
}

/**
 * The 64-bit implementation of the NIST specified Sigma1 function
 *
 * @param x The 64-bit integer argument
 * @returns The NIST specified output of the function
 */
export function sigma1_64(x: Int_64): Int_64 {
  const rotr14 = rotr_64(x, 14),
    rotr18 = rotr_64(x, 18),
    rotr41 = rotr_64(x, 41);

  return new Int_64(
    rotr14.highOrder ^ rotr18.highOrder ^ rotr41.highOrder,
    rotr14.lowOrder ^ rotr18.lowOrder ^ rotr41.lowOrder
  );
}
