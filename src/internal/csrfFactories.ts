// src/internal/csrfFactories.ts
import type { PrismaClient } from "@prisma/client";
import {
  clearCSRFForSession,
  createCSRFForSession,
  validateCSRFForSession,
} from "../auth/csrf";
import type { SpectraAuthConfig } from "../types";
import { createErrorResult } from "../utils/logger";

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
      return {
        error: false,
        status: 200,
        message: "CSRF token created successfully.",
        data: { cookieStr },
      };
    } catch (err) {
      config.logger.error("Error in createCSRF factory", { error: err });
      return createErrorResult(
        500,
        (err as Error).message || "Failed to create CSRF token",
      );
    }
  };
}

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
      return {
        error: false,
        status: 200,
        message: "CSRF token is valid.",
      };
    } catch (err) {
      config.logger.error("Error in validateCSRF factory", { error: err });
      return createErrorResult(
        500,
        (err as Error).message || "Failed to validate CSRF token",
      );
    }
  };
}

export function clearCSRFCookieFactory(config: Required<SpectraAuthConfig>) {
  return () => {
    try {
      const clearCookie = clearCSRFForSession(config);
      return {
        error: false,
        status: 200,
        message: "CSRF cookie cleared.",
        data: { clearCookie },
      };
    } catch (err) {
      config.logger.error("Error in clearCSRF factory", { error: err });
      return createErrorResult(
        500,
        (err as Error).message || "Failed to clear CSRF cookie",
      );
    }
  };
}
