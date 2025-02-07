import { getRandomValues } from "uncrypto";
import type { SpectraAuthConfig } from "../types";
import { hex } from "./hex"; // or base64 / base64url if you prefer
import { createHMAC } from "./hmac";

/**
 * Generates a random CSRF token (e.g., 32 bytes) and returns it as a hex string.
 *
 * @param size - Number of random bytes; 16-32 is typical.
 */
export function generateRandomCSRFToken(size = 32): string {
  const raw = new Uint8Array(size);
  getRandomValues(raw);
  return hex.encode(raw);
}

/**
 * Computes the HMAC of a raw CSRF token using the server-side `config.session.csrfSecret`.
 *
 * @param rawCsrfToken - The raw token string (unhashed) that will be stored in the cookie.
 * @param config       - Full config, containing `session.csrfSecret`.
 * @returns The HMAC (hex-encoded by default) of the raw token.
 */
export async function computeCsrfTokenHmac(
  rawCsrfToken: string,
  config: Required<SpectraAuthConfig>,
): Promise<string> {
  return createHMAC("SHA-256", "hex").sign(
    config.session.csrfSecret,
    rawCsrfToken,
  ) as Promise<string>; // We'll use hex-encoded signatures
}

/**
 * Verifies that a raw CSRF token’s HMAC matches the stored HMAC.
 *
 * @param rawCsrfToken - The raw token from the client cookie.
 * @param storedHmac   - The HMAC stored in the DB for this session.
 * @param config       - Full config with `session.csrfSecret`.
 * @returns true if the HMAC matches, otherwise false.
 */
export async function verifyCsrfHmac(
  rawCsrfToken: string,
  storedHmac: string,
  config: Required<SpectraAuthConfig>,
): Promise<boolean> {
  return createHMAC("SHA-256", "hex").verify(
    config.session.csrfSecret,
    rawCsrfToken,
    storedHmac,
  );
}
