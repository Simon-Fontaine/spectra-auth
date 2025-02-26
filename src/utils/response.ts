import type { ErrorCodeType } from "../constants";
import type { AegisError, AegisResponse } from "../types";

/**
 * Internal response utilities for standardizing operation results within the library.
 * These functions handle the internal data structure of responses and are not concerned
 * with HTTP-specific formatting.
 */

/**
 * Creates a successful response object
 */
export function success<T>(
  data: T,
  metadata?: Record<string, unknown>,
): AegisResponse<T> {
  return {
    success: true,
    data,
    error: null,
    ...(metadata && { metadata }),
  };
}

/**
 * Creates a failure response object
 */
export function fail<T>(
  code: ErrorCodeType,
  message: string,
  details?: Record<string, unknown>,
  metadata?: Record<string, unknown>,
): AegisResponse<T> {
  const error: AegisError = {
    code,
    message,
    ...(details && { details }),
  };

  return {
    success: false,
    data: null,
    error,
    ...(metadata && { metadata }),
  };
}

/**
 * Propagates an error from a previous operation
 */
export function propagate<T, U>(response: AegisResponse<T>): AegisResponse<U> {
  if (response.success) {
    throw new Error("Cannot propagate a successful response as an error");
  }

  return {
    success: false,
    data: null,
    error: response.error,
    metadata: response.metadata,
  };
}

/**
 * Merges two successful responses
 */
export function mergeResponses<T, U>(
  responseA: AegisResponse<T>,
  responseB: AegisResponse<U>,
): AegisResponse<{
  [K in keyof T | keyof U]: K extends keyof T
    ? T[K]
    : K extends keyof U
      ? U[K]
      : never;
}> {
  if (!responseA.success || !responseB.success) {
    throw new Error("Cannot merge responses when one or both are failures");
  }

  return success(
    {
      ...responseA.data,
      ...responseB.data,
    } as {
      [K in keyof T | keyof U]: K extends keyof T
        ? T[K]
        : K extends keyof U
          ? U[K]
          : never;
    },
    {
      ...responseA.metadata,
      ...responseB.metadata,
    },
  );
}

/**
 * Transforms a successful response's data
 */
export function transformResponse<T, U>(
  response: AegisResponse<T>,
  transformer: (data: T) => U,
): AegisResponse<U> {
  if (!response.success) {
    return propagate(response);
  }

  return success(transformer(response.data), response.metadata);
}
