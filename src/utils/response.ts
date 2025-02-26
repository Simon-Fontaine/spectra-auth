import type { ErrorCodeType } from "../constants";
import type { AegisError, AegisResponse } from "../types";

/**
 * Creates a successful response object
 *
 * @param data - The data to include in the response
 * @param metadata - Optional metadata to include
 * @returns A typed success response
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
 *
 * @param code - Error code identifying the type of error
 * @param message - Human-readable error message
 * @param details - Optional details about the error
 * @param metadata - Optional metadata to include
 * @returns A typed error response
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
 *
 * @param response - The previous error response
 * @returns A typed error response with the same error
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
 *
 * @param responseA - First successful response
 * @param responseB - Second successful response
 * @returns A merged successful response
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
 *
 * @param response - Original response
 * @param transformer - Function to transform the data
 * @returns A new response with transformed data
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
