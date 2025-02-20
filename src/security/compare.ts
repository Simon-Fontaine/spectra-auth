export function timingSafeEqual(
  a: ArrayBuffer | Uint8Array,
  b: ArrayBuffer | Uint8Array,
): boolean {
  const aBuffer = a instanceof Uint8Array ? a : new Uint8Array(a);
  const bBuffer = b instanceof Uint8Array ? b : new Uint8Array(b);

  if (aBuffer.length !== bBuffer.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < aBuffer.length; i++) {
    result |= aBuffer[i] ^ bBuffer[i];
  }

  return result === 0;
}
