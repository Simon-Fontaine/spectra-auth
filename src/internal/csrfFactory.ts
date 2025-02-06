import type { PrismaClient } from "@prisma/client";
import {
  ArgonType,
  hash as argon2Hash,
  verify as argon2Verify,
} from "argon2-browser";
import { serialize } from "cookie";
import { getRandomValues } from "uncrypto";
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
  async function createCSRFCookie(sessionToken: string): Promise<string> {
    // 1. Split session token => prefix/suffix
    const prefix = sessionToken.slice(0, 16);
    const suffix = sessionToken.slice(16);

    // 2. Find the session row
    const session = await prisma.session.findFirst({
      where: { tokenPrefix: prefix, isRevoked: false },
    });
    if (!session) throw new Error("Session not found.");

    // 3. Generate a random CSRF raw token
    const csrfRaw = new Uint8Array(24);
    getRandomValues(csrfRaw);
    const csrfRawHex = hex.encode(csrfRaw);

    // 4. Argon2-hash it
    const result = await argon2Hash({
      pass: csrfRawHex,
      salt: generateRandomSalt(16),
      type: ArgonType.Argon2id,
      mem: 512, // reduce further for performance
      time: 2,
      parallelism: 1,
    });

    // 5. Store the Argon2-encoded string in session.csrfSecret
    await prisma.session.update({
      where: { id: session.id },
      data: { csrfSecret: result.encoded },
    });

    // 6. Return the raw token in a cookie
    return serialize(CSRF_COOKIE_NAME, csrfRawHex, {
      httpOnly: false,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
      maxAge: config.session.maxAgeSec,
    });
  }

  function getCSRFTokenFromCookies(
    cookieHeader: string | undefined,
  ): string | null {
    if (!cookieHeader) return null;
    const parts = cookieHeader.split(";").map((c) => c.trim().split("="));
    const cookies = Object.fromEntries(parts);
    return cookies[CSRF_COOKIE_NAME] || null;
  }

  async function validateCSRFToken(
    sessionToken: string,
    rawCsrfCookieVal: string,
    submittedVal: string,
  ): Promise<boolean> {
    // 1. Lookup session
    const prefix = sessionToken.slice(0, 16);
    const session = await prisma.session.findFirst({
      where: { tokenPrefix: prefix, isRevoked: false },
    });
    if (!session || !session.csrfSecret) return false;

    // 2. Compare cookie vs. submitted
    if (rawCsrfCookieVal !== submittedVal) return false;

    // 3. Argon2-verify with the stored hash
    try {
      await argon2Verify({
        pass: rawCsrfCookieVal,
        encoded: session.csrfSecret,
        type: ArgonType.Argon2id,
      });
      return true;
    } catch {
      return false;
    }
  }

  return {
    createCSRFCookie,
    getCSRFTokenFromCookies,
    validateCSRFToken,
  };
}

/**
 * Helper for random salt.
 */
function generateRandomSalt(bytes: number): Uint8Array {
  const salt = new Uint8Array(bytes);
  getRandomValues(salt);
  return salt;
}
