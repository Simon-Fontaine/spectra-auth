import type { SpectraAuthConfig, SpectraAuthResult } from "../types";

/**
 * Creates a standardized error result, logs it with `logger.error`.
 *
 * @param config - The full config object (needs `.logger`).
 * @param err - The raw error object caught in a try/catch.
 * @param logContext - A short string describing where the error happened (for logs).
 * @param fallbackMessage - If `err` has no message, use this.
 * @param status - The HTTP-like status code to return. Defaults to 500.
 * @param code - An optional error code string (e.g. "E_SESSION_NOT_FOUND").
 */
export function formatErrorResult(
  config: Required<SpectraAuthConfig>,
  err: unknown,
  logContext: string,
  fallbackMessage: string,
  status = 500,
  code?: string,
): SpectraAuthResult {
  config.logger.error(logContext, { error: err });

  // If the error is an actual Error instance with a message, we use it; otherwise fallback.
  const message =
    err instanceof Error && err.message ? err.message : fallbackMessage;

  return {
    error: true,
    status,
    message,
    ...(code ? { code } : {}),
  };
}

/**
 * Creates a standardized success result (no logging needed here).
 *
 * @param status - The HTTP-like status code for success (e.g. 200 or 201).
 * @param message - A human-readable success message.
 * @param data - Optional data object to return.
 */
export function formatSuccessResult(
  status: number,
  message: string,
  data?: Record<string, unknown>,
): SpectraAuthResult {
  return {
    error: false,
    status,
    message,
    ...(data ? { data } : {}),
  };
}
