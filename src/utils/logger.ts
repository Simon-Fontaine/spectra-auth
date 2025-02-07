import type { LoggerInterface, SpectraAuthResult } from "../types";

export function createErrorResult(
  status: number,
  message: string,
  code?: string,
): SpectraAuthResult {
  return { error: true, status, message, code };
}

export function createSuccessResult(
  status: number,
  message: string,
  data?: Record<string, unknown>,
): SpectraAuthResult {
  return { error: false, status, message, data };
}

export const consoleLogger: LoggerInterface = {
  info: (msg, meta) =>
    console.info(
      `[SpectraAuth INFO] ${msg}`,
      meta ? `\nMetadata: ${JSON.stringify(meta)}` : "",
    ),
  warn: (msg, meta) =>
    console.warn(
      `[SpectraAuth WARN] ${msg}`,
      meta ? `\nMetadata: ${JSON.stringify(meta)}` : "",
    ),
  error: (msg, meta) =>
    console.error(
      `[SpectraAuth ERROR] ${msg}`,
      meta ? `\nMetadata: ${JSON.stringify(meta)}` : "",
    ),
  securityEvent: (eventType, meta) =>
    console.log(
      `[SpectraAuth SECURITY EVENT] ${eventType}`,
      `\nMetadata: ${JSON.stringify(meta)}`,
    ),
};
