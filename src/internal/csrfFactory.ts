import { serialize } from "cookie";
import { createHMAC } from "../crypto/hmac";
import type { SpectraAuthConfig } from "../types";

/**
 * We'll define an interface for the methods we want to expose.
 */
export interface CSRFHelpers {
  createCSRFCookie(sessionToken: string): Promise<string>;
  getCSRFTokenFromCookies(cookieHeader: string | undefined): string | null;
  validateCSRFToken(
    sessionToken: string,
    csrfCookieVal: string,
    csrfSubmittedVal: string,
  ): Promise<boolean>;
}

const CSRF_COOKIE_NAME = "spectra.csrfToken";

async function generateCSRFToken(sessionToken: string, secret: string) {
  // HMAC-based approach
  return await createHMAC("SHA-256", "hex").sign(secret, sessionToken);
}

/**
 * Factory returning an object with CSRF functions,
 * capturing config in a closure.
 */
export function csrfFactory(config: Required<SpectraAuthConfig>): CSRFHelpers {
  const { csrf, session, logger } = config;

  async function createCSRFCookie(sessionToken: string): Promise<string> {
    const csrfToken = await generateCSRFToken(sessionToken, csrf.secret);
    logger.info("CSRF cookie created");
    return serialize(CSRF_COOKIE_NAME, csrfToken, {
      httpOnly: false, // must be readable by JS
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
      maxAge: session.maxAgeSec,
    });
  }

  function getCSRFTokenFromCookies(
    cookieHeader: string | undefined,
  ): string | null {
    if (!cookieHeader) return null;
    const cookies = cookieHeader.split(";").map((c) => c.trim().split("="));
    const cookieObj = Object.fromEntries(cookies);
    return cookieObj[CSRF_COOKIE_NAME] || null;
  }

  async function validateCSRFToken(
    sessionToken: string,
    csrfCookieVal: string,
    csrfHeaderOrBodyVal: string,
  ): Promise<boolean> {
    const expected = await generateCSRFToken(sessionToken, csrf.secret);
    return expected === csrfCookieVal && expected === csrfHeaderOrBodyVal;
  }

  return {
    createCSRFCookie,
    getCSRFTokenFromCookies,
    validateCSRFToken,
  };
}
