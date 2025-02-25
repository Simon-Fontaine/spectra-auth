import { subtle } from "uncrypto";
import type { AegisAuthConfig, AegisResponse } from "../types";
import { fail, success } from "./response";

interface FingerprintOptions {
  ip?: string;
  userAgent?: string;
  headers: Headers;
  config: AegisAuthConfig;
}

/**
 * Generates a browser fingerprint based on available client information
 *
 * @param ip - The client IP address (optional)
 * @param userAgent - The client user agent string (optional)
 * @param headers - Request headers
 * @param config - Authentication configuration
 * @returns A response with the generated fingerprint hash or an error
 */
export async function generateBrowserFingerprint({
  ip,
  userAgent,
  headers,
  config,
}: FingerprintOptions): Promise<AegisResponse<string>> {
  try {
    const factors: string[] = [];

    // Include IP if configured
    if (ip && config.session.fingerprintOptions?.includeIp) {
      factors.push(`ip:${ip}`);
    }

    // User agent provides browser and OS info
    if (userAgent) {
      factors.push(`ua:${userAgent}`);
    }

    // Accept-Language header indicates user's language preferences
    const acceptLanguage = headers.get("accept-language");
    if (acceptLanguage) {
      factors.push(`lang:${acceptLanguage}`);
    }

    // Custom header for screen information
    const screenInfo = headers.get("x-screen-info");
    if (screenInfo) {
      factors.push(`screen:${screenInfo}`);
    }

    // Custom header for timezone
    const timezone = headers.get("x-timezone");
    if (timezone) {
      factors.push(`tz:${timezone}`);
    }

    // Sec-CH headers (Client Hints) if available
    const secChUa = headers.get("sec-ch-ua");
    if (secChUa) {
      factors.push(`ua-brands:${secChUa}`);
    }

    const secChUaMobile = headers.get("sec-ch-ua-mobile");
    if (secChUaMobile) {
      factors.push(`ua-mobile:${secChUaMobile}`);
    }

    const secChUaPlatform = headers.get("sec-ch-ua-platform");
    if (secChUaPlatform) {
      factors.push(`ua-platform:${secChUaPlatform}`);
    }

    // Check if we have enough data for a useful fingerprint
    if (factors.length < 2) {
      return fail(
        "FINGERPRINT_INSUFFICIENT_DATA",
        "Insufficient information to generate a reliable fingerprint",
      );
    }

    // Sort factors for consistent ordering
    const fingerprintInput = factors.sort().join("|");

    // Generate a SHA-256 hash of the fingerprint data
    const encoder = new TextEncoder();
    const data = encoder.encode(fingerprintInput);
    const hashBuffer = await subtle.digest("SHA-256", data);

    // Convert hash to hex string
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    return success(hashHex);
  } catch (error) {
    return fail(
      "FINGERPRINT_GENERATION_ERROR",
      "Failed to generate browser fingerprint",
    );
  }
}

/**
 * Validates a session's fingerprint against the current client fingerprint
 *
 * @param currentFingerprint - The fingerprint generated from the current request
 * @param storedFingerprint - The fingerprint stored with the session
 * @param config - Authentication configuration
 * @returns A response with validation result or an error
 */
export async function validateSessionFingerprint(
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
        return fail("FINGERPRINT_MISSING", "Session fingerprint missing");
      }
      return success(true);
    }

    // Check for exact match first
    const exactMatch = currentFingerprint === storedFingerprint;

    // For non-strict validation, just return the match result
    if (!config.session.fingerprintOptions?.strictValidation) {
      return success(exactMatch);
    }

    // In strict mode, fail if there's a mismatch
    if (!exactMatch) {
      return fail(
        "FINGERPRINT_MISMATCH",
        "Session fingerprint mismatch detected",
      );
    }

    return success(true);
  } catch (error) {
    return fail(
      "FINGERPRINT_VALIDATION_ERROR",
      "Failed to validate fingerprint",
    );
  }
}

/**
 * Calculates similarity between two fingerprints
 * This helps handle minor browser updates that slightly change the fingerprint
 *
 * @param fingerprintA - First fingerprint
 * @param fingerprintB - Second fingerprint
 * @returns Similarity score between 0 and 1
 */
export function calculateFingerprintSimilarity(
  fingerprintA: string,
  fingerprintB: string,
): number {
  // Simple implementation: count matching characters
  if (fingerprintA.length !== fingerprintB.length) {
    return 0;
  }

  let matchingChars = 0;
  for (let i = 0; i < fingerprintA.length; i++) {
    if (fingerprintA[i] === fingerprintB[i]) {
      matchingChars++;
    }
  }

  return matchingChars / fingerprintA.length;
}
