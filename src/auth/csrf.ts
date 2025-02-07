import type { PrismaClient } from "@prisma/client";
import {
  clearCSRFCookie,
  createCSRFCookie,
  getCSRFTokenFromHeaders,
} from "../cookies/csrf";
import {
  computeCsrfTokenHmac,
  generateRandomCSRFToken,
  verifyCsrfHmac,
} from "../crypto/csrf-token";
import type { SpectraAuthConfig } from "../types";

/**
 * Creates a new CSRF token for the given session by:
 *  1. Generating a random token (raw),
 *  2. Computing the HMAC (with config.session.csrfSecret),
 *  3. Storing that HMAC in the DB,
 *  4. Returning the Set-Cookie header string for the raw token.
 */
export async function createCSRFForSession(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  sessionToken: string,
): Promise<string> {
  if (!config.csrf.enabled) {
    // If CSRF is disabled, return an empty header
    return "";
  }

  const tokenPrefix = sessionToken.slice(
    0,
    config.session.tokenPrefixLengthBytes * 2,
  );

  const session = await prisma.session.findFirst({
    where: { tokenPrefix, isRevoked: false },
  });
  if (!session) throw new Error("Session not found or is revoked.");

  const rawCsrfToken = generateRandomCSRFToken(32);
  const hmac = await computeCsrfTokenHmac(rawCsrfToken, config);

  await prisma.session.update({
    where: { id: session.id },
    data: { csrfSecret: hmac },
  });

  return createCSRFCookie(rawCsrfToken, config);
}

/**
 * Validates a submitted CSRF token for a given session token.
 *  - Extracts raw token from cookie and request body/header
 *  - Recomputes HMAC, compares with DB
 *  - Returns true if valid, else false
 */
export async function validateCSRFForSession(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  sessionToken: string,
  cookieHeader: string | undefined,
  csrfSubmittedVal: string | undefined,
): Promise<boolean> {
  if (!config.csrf.enabled) return true; // If disabled, skip check

  const rawCsrfCookieVal = getCSRFTokenFromHeaders(cookieHeader, config);
  if (!rawCsrfCookieVal || !csrfSubmittedVal) {
    config.logger.warn("CSRF validation: missing tokens", {
      hasCookieVal: !!rawCsrfCookieVal,
      hasSubmittedVal: !!csrfSubmittedVal,
    });
    return false;
  }

  if (rawCsrfCookieVal !== csrfSubmittedVal) {
    config.logger.warn("CSRF mismatch: cookie vs. submitted mismatch");
    return false;
  }

  const tokenPrefix = sessionToken.slice(
    0,
    config.session.tokenPrefixLengthBytes * 2,
  );
  const session = await prisma.session.findFirst({
    where: { tokenPrefix, isRevoked: false },
  });
  if (!session) {
    config.logger.warn("CSRF validation: session not found or revoked");
    return false;
  }
  if (!session.csrfSecret) {
    config.logger.warn("CSRF validation: no csrfSecret in session");
    return false;
  }

  const valid = await verifyCsrfHmac(
    rawCsrfCookieVal,
    session.csrfSecret,
    config,
  );
  if (!valid) config.logger.warn("CSRF validation: HMAC mismatch");
  return valid;
}

/**
 * Clears the CSRF cookie (e.g., on logout).
 */
export function clearCSRFForSession(
  config: Required<SpectraAuthConfig>,
): string {
  return clearCSRFCookie(config);
}
