import type { PrismaClient } from "@prisma/client";
import { serialize } from "cookie";
import { getRandomValues } from "uncrypto";
import { hashArgon2, verifyArgon2 } from "../crypto/argon2Utils";
import { timingSafeEqual } from "../crypto/buffer";
import { hex } from "../crypto/hex";
import type { SpectraAuthConfig } from "../types";

const CSRF_COOKIE_NAME = "spectra.csrfToken";

export interface CSRFHelpers {
  createCSRFCookie(sessionToken: string): Promise<string>;
  getCSRFTokenFromCookies(cookieHeader: string | undefined): string | null;
  validateCSRFToken(
    sessionToken: string,
    rawCsrfCookieVal: string,
    submittedVal: string,
  ): Promise<boolean>;
}

export function csrfFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
): CSRFHelpers {
  /**
   * Creates a CSRF cookie linked to the session.
   *
   * - Generates a random token.
   * - Hashes the token using Argon2 and stores it securely.
   * - Returns the raw token as a cookie for the client.
   */
  async function createCSRFCookie(sessionToken: string): Promise<string> {
    // Step 1: Split session token into prefix and suffix
    const prefix = sessionToken.slice(0, 16);
    const suffix = sessionToken.slice(16);

    // Step 2: Find the session associated with the token prefix
    const session = await prisma.session.findFirst({
      where: { tokenPrefix: prefix, isRevoked: false },
    });
    if (!session) throw new Error("Session not found.");

    // Step 3: Generate a random CSRF token
    const csrfRaw = new Uint8Array(24);
    getRandomValues(csrfRaw);
    const csrfRawHex = hex.encode(csrfRaw);

    // Step 4: Hash the token with Argon2id (WASM-friendly)
    const hashed = await hashArgon2(csrfRawHex, {
      mem: 1024, // Slightly stronger memory usage
      time: 3, // Increased iterations for security
      parallelism: 1, // Single-threaded (WASM compatibility)
      saltSize: 16,
    });

    // Step 5: Store the hashed CSRF token in the session
    await prisma.session.update({
      where: { id: session.id },
      data: { csrfSecret: hashed },
    });

    // Step 6: Return the CSRF token in a client cookie
    return serialize(CSRF_COOKIE_NAME, csrfRawHex, {
      httpOnly: false,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: config.session.maxAgeSec,
      domain: process.env.COOKIE_DOMAIN,
      partitioned: true,
    });
  }

  /**
   * Extracts the CSRF token from cookies.
   *
   * @param cookieHeader - The raw cookie header from the client request.
   * @returns The CSRF token if present, or `null`.
   */
  function getCSRFTokenFromCookies(
    cookieHeader: string | undefined,
  ): string | null {
    if (!cookieHeader) return null;
    const parts = cookieHeader.split(";").map((c) => c.trim().split("="));
    const cookies = Object.fromEntries(parts);
    return cookies[CSRF_COOKIE_NAME] || null;
  }

  /**
   * Validates the CSRF token by comparing the provided token with the stored hash.
   *
   * - Looks up the session associated with the session token.
   * - Performs a timing-safe comparison to prevent timing attacks.
   * - Verifies the CSRF token using Argon2id.
   *
   * @param sessionToken - The session token for identifying the session.
   * @param rawCsrfCookieVal - The raw CSRF token from the client's cookie.
   * @param submittedVal - The CSRF token submitted in the request.
   * @returns `true` if the tokens are valid, otherwise `false`.
   */
  async function validateCSRFToken(
    sessionToken: string,
    rawCsrfCookieVal: string,
    submittedVal: string,
  ): Promise<boolean> {
    // Step 1: Find the session associated with the session token prefix
    const prefix = sessionToken.slice(0, 16);
    const session = await prisma.session.findFirst({
      where: { tokenPrefix: prefix, isRevoked: false },
    });
    if (!session || !session.csrfSecret) return false;

    // Step 2: Perform a timing-safe comparison of the cookie and submitted tokens
    if (
      !timingSafeEqual(Buffer.from(rawCsrfCookieVal), Buffer.from(submittedVal))
    ) {
      return false;
    }

    // Step 3: Verify the CSRF token using Argon2id
    return verifyArgon2(session.csrfSecret, rawCsrfCookieVal);
  }

  return {
    createCSRFCookie,
    getCSRFTokenFromCookies,
    validateCSRFToken,
  };
}
