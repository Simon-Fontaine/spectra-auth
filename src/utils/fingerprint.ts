import { subtle } from "uncrypto";
import type { AegisAuthConfig, AegisResponse } from "../types";
import { fail, success } from "./response";

interface FingerprintOptions {
  ip?: string;
  userAgent?: string;
  headers: Headers;
  config: AegisAuthConfig;
}

export async function generateBrowserFingerprint({
  ip,
  userAgent,
  headers,
  config,
}: FingerprintOptions): Promise<AegisResponse<string>> {
  try {
    const factors: string[] = [];

    if (ip && config.session.fingerprintOptions?.includeIp) {
      factors.push(`ip:${ip}`);
    }

    if (userAgent) {
      factors.push(`ua:${userAgent}`);
    }

    const acceptLanguage = headers.get("accept-language");
    if (acceptLanguage) {
      factors.push(`lang:${acceptLanguage}`);
    }

    const screenInfo = headers.get("x-screen-info");
    if (screenInfo) {
      factors.push(`screen:${screenInfo}`);
    }

    const timezone = headers.get("x-timezone");
    if (timezone) {
      factors.push(`tz:${timezone}`);
    }

    if (factors.length === 0) {
      return fail(
        "FINGERPRINT_NO_FACTORS",
        "Insufficient information to generate a fingerprint",
      );
    }

    const fingerprintInput = factors.sort().join("|");

    const encoder = new TextEncoder();
    const data = encoder.encode(fingerprintInput);
    const hashBuffer = await subtle.digest("SHA-256", data);

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

export async function validateSessionFingerprint(
  currentFingerprint: string,
  storedFingerprint: string | undefined,
  config: AegisAuthConfig,
): Promise<AegisResponse<boolean>> {
  try {
    if (!config.session.fingerprintOptions?.enabled) {
      return success(true);
    }

    if (!storedFingerprint) {
      if (config.session.fingerprintOptions?.strictValidation) {
        return fail("FINGERPRINT_MISSING", "Session fingerprint missing");
      }
      return success(true);
    }

    const exactMatch = currentFingerprint === storedFingerprint;

    if (!config.session.fingerprintOptions?.strictValidation) {
      return success(exactMatch);
    }

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
