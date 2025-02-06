/**
 * Performs a constant-time comparison of two buffers to prevent timing attacks.
 *
 * - Compares byte-by-byte to ensure that the comparison time is always the same,
 *   regardless of where the difference occurs.
 *
 * @param a - The first buffer to compare.
 * @param b - The second buffer to compare.
 * @returns `true` if the buffers are equal, otherwise `false`.
 */
export function timingSafeEqual(
  a: ArrayBuffer | Uint8Array,
  b: ArrayBuffer | Uint8Array,
): boolean {
  const aBuffer = a instanceof Uint8Array ? a : new Uint8Array(a);
  const bBuffer = b instanceof Uint8Array ? b : new Uint8Array(b);

  // Return false immediately if the lengths are different
  if (aBuffer.length !== bBuffer.length) {
    return false;
  }

  let result = 0;

  // Compare each byte, accumulating differences using bitwise OR
  for (let i = 0; i < aBuffer.length; i++) {
    result |= aBuffer[i] ^ bBuffer[i];
  }

  // If result is 0, the buffers are equal
  return result === 0;
}
