import { getRandomValues } from "uncrypto";
import type { EncodingFormat } from "../types"; // Adjust path if necessary
import { base64Url } from "./base64";
import { hex } from "./hex";

function randomBytes(length: number): Uint8Array {
  return getRandomValues(new Uint8Array(length));
}

/**
 * Generates a cryptographically secure random session token.
 *
 * @param length The desired length of the token in bytes (default: 32 bytes, 256 bits).
 * @param format  Encoding format for the token ('base64' or 'hex', default: 'base64').
 * @returns A cryptographically secure random session token string.
 */
export async function generateSessionToken(
  length = 32,
  format: EncodingFormat = "base64",
): Promise<string> {
  if (length <= 0) {
    throw new Error("Token length must be greater than zero.");
  }

  try {
    const buffer = randomBytes(length);

    if (format === "hex") {
      return hex.encode(buffer);
    }

    if (format === "base64") {
      return base64Url.encode(buffer);
    }

    throw new Error(
      `Unsupported token format: ${format}. Use 'base64' or 'hex'.`,
    );
  } catch (error) {
    console.error("Session token generation failed:", error);
    throw new Error("Failed to generate session token.");
  }
}

/**
 * Generates a cryptographically secure random token prefix.
 *  Prefixes can be shorter and are used for indexing and faster session lookup.
 *
 * @param length Desired prefix length in bytes (default: 8 bytes, 64 bits).
 * @param format Encoding format ('base64' or 'hex', default: 'hex').
 * @returns A cryptographically secure random token prefix string.
 */
export async function generateTokenPrefix(
  length = 8,
  format: EncodingFormat = "hex",
): Promise<string> {
  if (length <= 0) {
    throw new Error("Token prefix length must be greater than zero.");
  }

  try {
    const buffer = randomBytes(length);

    if (format === "hex") {
      return hex.encode(buffer);
    }

    if (format === "base64") {
      return base64Url.encode(buffer);
    }

    throw new Error(
      `Unsupported token format: ${format}. Use 'base64' or 'hex'.`,
    );
  } catch (error) {
    console.error("Token prefix generation failed:", error);
    throw new Error("Failed to generate token prefix.");
  }
}
