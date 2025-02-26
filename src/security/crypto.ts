import { getRandomValues, subtle } from "uncrypto";
import { ErrorCode } from "../constants";
import type {
  AegisResponse,
  EncodingFormat,
  SHAFamily,
  TypedArray,
} from "../types";
import { fail, success } from "../utils/response";

/**
 * Generates cryptographically secure random bytes
 *
 * @param length - Number of bytes to generate
 * @returns Response with random bytes or error
 */
export function generateRandomBytes(length: number): AegisResponse<Uint8Array> {
  try {
    const bytes = getRandomValues(new Uint8Array(length));
    return success(bytes);
  } catch (error) {
    return fail(
      ErrorCode.SECURITY_TOKEN_ERROR,
      "Failed to generate secure random bytes",
    );
  }
}

/**
 * Encodes a buffer as a hex string
 *
 * @param buffer - Data to encode
 * @returns Hex string
 */
export function encodeHex(buffer: ArrayBuffer | TypedArray): string {
  const bytes = new Uint8Array(
    buffer instanceof ArrayBuffer ? buffer : buffer.buffer,
  );
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Decodes a hex string to a Uint8Array
 *
 * @param hex - Hex string to decode
 * @returns Decoded bytes
 */
export function decodeHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("Invalid hex string length");
  }

  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = Number.parseInt(hex.substring(i, i + 2), 16);
  }

  return bytes;
}

/**
 * Encodes data as base64
 *
 * @param data - Data to encode
 * @param urlSafe - Whether to use URL-safe base64
 * @returns Base64 string
 */
export function encodeBase64(
  data: ArrayBuffer | TypedArray | string,
  urlSafe = false,
): string {
  // Convert string to bytes if needed
  const bytes =
    typeof data === "string"
      ? new TextEncoder().encode(data)
      : new Uint8Array(data instanceof ArrayBuffer ? data : data.buffer);

  // Convert to standard base64
  let base64 = btoa(String.fromCharCode(...bytes));

  // Make URL-safe if requested
  if (urlSafe) {
    base64 = base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  return base64;
}

/**
 * Decodes base64 data
 *
 * @param base64 - Base64 string to decode
 * @param urlSafe - Whether the input is URL-safe base64
 * @returns Decoded bytes
 */
export function decodeBase64(base64: string, urlSafe = false): Uint8Array {
  // Convert from URL-safe if needed
  let normalizedBase64 = base64;
  if (urlSafe) {
    normalizedBase64 = normalizedBase64.replace(/-/g, "+").replace(/_/g, "/");
    // Add padding if needed
    while (normalizedBase64.length % 4) {
      normalizedBase64 += "=";
    }
  }

  // Decode base64
  const binaryString = atob(normalizedBase64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }

  return bytes;
}

/**
 * Creates a message digest using the specified algorithm
 *
 * @param algorithm - Hash algorithm to use
 * @param data - Data to hash
 * @param encoding - Output encoding format
 * @returns Response with hashed data
 */
export async function createHash(
  algorithm: SHAFamily,
  data: ArrayBuffer | TypedArray | string,
  encoding: EncodingFormat = "hex",
): Promise<AegisResponse<string>> {
  try {
    // Convert string to bytes if needed
    const bytes =
      typeof data === "string"
        ? new TextEncoder().encode(data)
        : new Uint8Array(data instanceof ArrayBuffer ? data : data.buffer);

    // Generate hash
    const hashBuffer = await subtle.digest(algorithm, bytes);

    // Encode output in the requested format
    let output: string;
    switch (encoding) {
      case "hex":
        output = encodeHex(hashBuffer);
        break;
      case "base64":
        output = encodeBase64(hashBuffer, false);
        break;
      case "base64url":
      case "base64urlnopad":
        output = encodeBase64(hashBuffer, true);
        break;
      default:
        return fail(
          ErrorCode.SECURITY_HASH_ERROR,
          `Unsupported encoding format: ${encoding}`,
        );
    }

    return success(output);
  } catch (error) {
    return fail(ErrorCode.SECURITY_HASH_ERROR, "Failed to create hash");
  }
}

/**
 * Creates an HMAC signature
 *
 * @param algorithm - Hash algorithm to use
 * @param key - Secret key
 * @param data - Data to sign
 * @param encoding - Output encoding format
 * @returns Response with the signature
 */
export async function createHmac(
  algorithm: SHAFamily,
  key: string | ArrayBuffer | TypedArray,
  data: string | ArrayBuffer | TypedArray,
  encoding: EncodingFormat = "hex",
): Promise<AegisResponse<string>> {
  try {
    // Convert key to bytes if needed
    const keyBytes =
      typeof key === "string"
        ? new TextEncoder().encode(key)
        : new Uint8Array(key instanceof ArrayBuffer ? key : key.buffer);

    // Convert data to bytes if needed
    const dataBytes =
      typeof data === "string"
        ? new TextEncoder().encode(data)
        : new Uint8Array(data instanceof ArrayBuffer ? data : data.buffer);

    // Import key for HMAC
    const cryptoKey = await subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: { name: algorithm } },
      false,
      ["sign"],
    );

    // Create signature
    const signatureBuffer = await subtle.sign("HMAC", cryptoKey, dataBytes);

    // Encode output in the requested format
    let output: string;
    switch (encoding) {
      case "hex":
        output = encodeHex(signatureBuffer);
        break;
      case "base64":
        output = encodeBase64(signatureBuffer, false);
        break;
      case "base64url":
      case "base64urlnopad":
        output = encodeBase64(signatureBuffer, true);
        break;
      default:
        return fail(
          ErrorCode.SECURITY_HASH_ERROR,
          `Unsupported encoding format: ${encoding}`,
        );
    }

    return success(output);
  } catch (error) {
    return fail(
      ErrorCode.SECURITY_HASH_ERROR,
      "Failed to create HMAC signature",
    );
  }
}

/**
 * Verifies an HMAC signature
 *
 * @param algorithm - Hash algorithm used
 * @param key - Secret key
 * @param data - Original data
 * @param signature - Signature to verify
 * @param encoding - Signature encoding format
 * @returns Response with verification result
 */
export async function verifyHmac(
  algorithm: SHAFamily,
  key: string | ArrayBuffer | TypedArray,
  data: string | ArrayBuffer | TypedArray,
  signature: string,
  encoding: EncodingFormat = "hex",
): Promise<AegisResponse<boolean>> {
  try {
    // Convert key to bytes if needed
    const keyBytes =
      typeof key === "string"
        ? new TextEncoder().encode(key)
        : new Uint8Array(key instanceof ArrayBuffer ? key : key.buffer);

    // Convert data to bytes if needed
    const dataBytes =
      typeof data === "string"
        ? new TextEncoder().encode(data)
        : new Uint8Array(data instanceof ArrayBuffer ? data : data.buffer);

    // Convert signature to bytes based on encoding
    let signatureBytes: Uint8Array;
    switch (encoding) {
      case "hex":
        signatureBytes = decodeHex(signature);
        break;
      case "base64":
        signatureBytes = decodeBase64(signature, false);
        break;
      case "base64url":
      case "base64urlnopad":
        signatureBytes = decodeBase64(signature, true);
        break;
      default:
        return fail(
          ErrorCode.SECURITY_HASH_ERROR,
          `Unsupported encoding format: ${encoding}`,
        );
    }

    // Import key for HMAC
    const cryptoKey = await subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: { name: algorithm } },
      false,
      ["verify"],
    );

    // Verify signature
    const isValid = await subtle.verify(
      "HMAC",
      cryptoKey,
      signatureBytes,
      dataBytes,
    );

    return success(isValid);
  } catch (error) {
    return fail(
      ErrorCode.SECURITY_HASH_ERROR,
      "Failed to verify HMAC signature",
    );
  }
}

/**
 * Performs constant-time comparison of two byte arrays to prevent timing attacks
 *
 * @param a - First byte array
 * @param b - Second byte array
 * @returns True if the arrays are equal
 */
export function timingSafeEqual(
  a: ArrayBuffer | TypedArray,
  b: ArrayBuffer | TypedArray,
): boolean {
  const aBytes = new Uint8Array(a instanceof ArrayBuffer ? a : a.buffer);
  const bBytes = new Uint8Array(b instanceof ArrayBuffer ? b : b.buffer);

  if (aBytes.length !== bBytes.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < aBytes.length; i++) {
    result |= aBytes[i] ^ bBytes[i];
  }

  return result === 0;
}
