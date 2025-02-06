import type { SpectraAuthResult } from "../types";

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
