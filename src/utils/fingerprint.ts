import { subtle } from "uncrypto";
import { ErrorCode } from "../constants";
import type { AegisAuthConfig, AegisResponse } from "../types";
import { fail, success } from "./response";

interface FingerprintOptions {
  ip?: string;
  userAgent?: string;
  headers: Headers;
  config: AegisAuthConfig;
}

/**
 * Generates a browser fingerprint based on request data
 *
 * @param options - Fingerprint generation options
 * @returns Response with the generated fingerprint or error
 */
export async function generateFingerprint(
  options: FingerprintOptions,
): Promise<AegisResponse<string>> {
  try {
    const { ip, userAgent, headers, config } = options;
    const factors: string[] = [];

    // Include IP address if configured and available
    if (ip && config.session.fingerprintOptions?.includeIp) {
      factors.push(`ip:${ip}`);
    }

    // Include user agent if available
    if (userAgent) {
      factors.push(`ua:${userAgent}`);
    }

    // Common headers that help identify the browser
    const headerFactors = [
      ["accept-language", "lang"],
      ["accept", "accept"],
      ["accept-encoding", "enc"],
      ["dnt", "dnt"], // Do Not Track
      ["sec-ch-ua", "ua-brands"],
      ["sec-ch-ua-mobile", "ua-mobile"],
      ["sec-ch-ua-platform", "ua-platform"],
      ["sec-ch-ua-platform-version", "ua-platform-ver"],
      ["sec-ch-width", "width"],
      ["sec-ch-viewport-width", "viewport-width"],
      ["sec-ch-device-memory", "device-memory"],
    ];

    // Add available header data
    for (const [headerName, factorName] of headerFactors) {
      const value = headers.get(headerName);
      if (value) {
        factors.push(`${factorName}:${value}`);
      }
    }

    // Custom headers for client hints
    const customHeaders = [
      "x-screen-info",
      "x-timezone",
      "x-color-depth",
      "x-device-pixel-ratio",
    ];

    for (const header of customHeaders) {
      const value = headers.get(header);
      if (value) {
        factors.push(`${header.replace("x-", "")}:${value}`);
      }
    }

    // Check if we have enough data for a useful fingerprint
    if (factors.length < 2) {
      return fail(
        ErrorCode.FINGERPRINT_INSUFFICIENT_DATA,
        "Insufficient information to generate a reliable fingerprint",
      );
    }

    // Sort factors for consistent ordering
    const fingerprintData = factors.sort().join("|");

    // Generate SHA-256 hash
    const encoder = new TextEncoder();
    const data = encoder.encode(fingerprintData);
    const hashBuffer = await subtle.digest("SHA-256", data);

    // Convert to hex string
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    return success(hashHex);
  } catch (error) {
    return fail(
      ErrorCode.FINGERPRINT_GENERATION_ERROR,
      "Failed to generate browser fingerprint",
    );
  }
}

/**
 * Validates current fingerprint against stored fingerprint
 *
 * @param currentFingerprint - Fingerprint from current request
 * @param storedFingerprint - Fingerprint stored with session
 * @param config - Authentication configuration
 * @returns Response with validation result
 */
export async function validateFingerprint(
  currentFingerprint: string,
  storedFingerprint: string | undefined,
  config: AegisAuthConfig,
): Promise<AegisResponse<boolean>> {
  try {
    // Skip validation if fingerprinting is disabled
    if (!config.session.fingerprintOptions?.enabled) {
      return success(true);
    }

    // Handle missing stored fingerprint
    if (!storedFingerprint) {
      if (config.session.fingerprintOptions?.strictValidation) {
        return fail(
          ErrorCode.FINGERPRINT_MISSING,
          "Session fingerprint missing",
        );
      }
      return success(true);
    }

    // Check for exact match
    const exactMatch = currentFingerprint === storedFingerprint;

    // For non-strict validation, calculate similarity for fuzzy matching
    if (!exactMatch && !config.session.fingerprintOptions?.strictValidation) {
      const similarity = calculateSimilarity(
        currentFingerprint,
        storedFingerprint,
      );
      // Accept if similarity is above threshold (80%)
      if (similarity > 0.8) {
        return success(true);
      }
    }

    // In strict mode or below similarity threshold
    if (!exactMatch) {
      return fail(
        ErrorCode.FINGERPRINT_MISMATCH,
        "Session fingerprint mismatch detected",
      );
    }

    return success(true);
  } catch (error) {
    return fail(
      ErrorCode.FINGERPRINT_VALIDATION_ERROR,
      "Failed to validate fingerprint",
    );
  }
}

/**
 * Calculates the similarity between two fingerprints
 *
 * @param a - First fingerprint
 * @param b - Second fingerprint
 * @returns Similarity score between 0 and 1
 */
export function calculateSimilarity(a: string, b: string): number {
  if (a === b) return 1;
  if (a.length !== b.length) return 0;

  let matchingChars = 0;

  for (let i = 0; i < a.length; i++) {
    if (a[i] === b[i]) {
      matchingChars++;
    }
  }

  return matchingChars / a.length;
}
