import type { PrismaClient } from "@prisma/client";
import {
  clearCSRFForSession,
  createCSRFForSession,
  validateCSRFForSession,
} from "../auth/csrf";
import type { SpectraAuthConfig } from "../types";
import { formatErrorResult, formatSuccessResult } from "../utils/formatResult";

/**
 * Creates a factory function for generating CSRF cookies associated with sessions.
 *
 * @param prisma - The Prisma client instance for database operations
 * @param config - The complete configuration object for Spectra Auth
 * @returns An async function that takes a session token and returns a result containing
 * either a CSRF cookie string on success or an error message on failure
 *
 * The returned function:
 * - Creates a new CSRF token for the given session
 * - Returns a success result with cookie string if successful
 * - Returns an error result with details if creation fails
 *
 * @throws Will return an error result rather than throwing if any errors occur
 */
export function createCSRFCookieFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (sessionToken: string) => {
    try {
      const cookieStr = await createCSRFForSession(
        prisma,
        config,
        sessionToken,
      );
      return formatSuccessResult(200, "CSRF token created successfully.", {
        cookieStr,
      });
    } catch (err) {
      return formatErrorResult(
        config,
        err,
        "Error in createCSRF factory",
        "Failed to create CSRF token",
        500,
      );
    }
  };
}

/**
 * Creates a function to validate CSRF tokens against a session cookie.
 *
 * @param prisma - The Prisma client instance used for database operations
 * @param config - The complete SpectraAuth configuration object
 * @returns An async function that validates CSRF tokens with the following parameters:
 *   - sessionToken: The session token string to validate against
 *   - cookieHeader: The raw cookie header string from the request
 *   - csrfSubmittedVal: The CSRF token value submitted with the request
 *
 * The returned function will return an object with:
 * - On success: {error: false, status: 200, message: string}
 * - On CSRF validation failure: {error: true, status: 403, message: string}
 * - On error: {error: true, status: number, message: string, trace?: string}
 */
export function validateCSRFCookieFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (
    sessionToken: string,
    cookieHeader: string | undefined,
    csrfSubmittedVal: string | undefined,
  ) => {
    try {
      const isValid = await validateCSRFForSession(
        prisma,
        config,
        sessionToken,
        cookieHeader,
        csrfSubmittedVal,
      );
      if (!isValid) {
        return {
          error: true,
          status: 403,
          message: "Invalid CSRF token.",
        };
      }
      return formatSuccessResult(200, "CSRF token is valid.");
    } catch (err) {
      return formatErrorResult(
        config,
        err,
        "Error in validateCSRF factory",
        "Failed to validate CSRF token",
        500,
      );
    }
  };
}

/**
 * Creates a factory function that handles clearing CSRF cookies.
 *
 * @param config - The complete Spectra Auth configuration object
 * @returns A function that when called:
 *  - Attempts to clear the CSRF cookie for the current session
 *  - Returns a success response (200) if successful
 *  - Returns an error response (500) if clearing fails
 *
 * @throws Will handle and format any errors that occur during cookie clearing
 * @see clearCSRFForSession
 * @see formatSuccessResult
 * @see formatErrorResult
 */
export function clearCSRFCookieFactory(config: Required<SpectraAuthConfig>) {
  return () => {
    try {
      const clearCookie = clearCSRFForSession(config);
      return formatSuccessResult(200, "CSRF cookie cleared.", { clearCookie });
    } catch (err) {
      return formatErrorResult(
        config,
        err,
        "Error in clearCSRF factory",
        "Failed to clear CSRF cookie",
        500,
      );
    }
  };
}
