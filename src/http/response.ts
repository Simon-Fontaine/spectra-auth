import { ErrorCode } from "../constants";
import type { AegisError, AegisResponse } from "../types";
import { securityHeaders } from "./headers";

/**
 * Standard API response format
 */
export interface ApiResponse<T> {
  success: boolean;
  data: T | null;
  error?: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
  metadata?: Record<string, unknown>;
}

/**
 * Response options for formatting API responses
 */
export interface ResponseOptions {
  headers?: Record<string, string>;
  cookies?: string[];
  status?: number;
}

/**
 * Formats a successful response with standard structure
 *
 * @param data - Response data
 * @param options - Response options (headers, cookies, status)
 * @returns Formatted response object
 */
export function formatSuccessResponse<T>(
  data: T,
  options: ResponseOptions = {},
): {
  status: number;
  headers: Record<string, string>;
  body: ApiResponse<T>;
} {
  const { headers = {}, cookies = [], status = 200 } = options;

  // Combine headers
  const responseHeaders = {
    ...securityHeaders,
    "Content-Type": "application/json",
    ...headers,
  };

  // Add cookies if provided
  if (cookies.length > 0) {
    responseHeaders["Set-Cookie"] = cookies.join(", ");
  }

  // Format body
  const body: ApiResponse<T> = {
    success: true,
    data,
  };

  return {
    status,
    headers: responseHeaders,
    body,
  };
}

/**
 * Formats an error response with standard structure
 *
 * @param error - Error object
 * @param options - Response options (headers, cookies, status)
 * @returns Formatted response object
 */
export function formatErrorResponse(
  error: AegisError,
  options: ResponseOptions = {},
): {
  status: number;
  headers: Record<string, string>;
  body: ApiResponse<null>;
} {
  const { headers = {}, cookies = [] } = options;

  // Determine status code based on error
  let status = options.status || 400; // Default to 400 Bad Request

  // Map common errors to appropriate status codes
  switch (error.code) {
    case ErrorCode.AUTH_NOT_AUTHENTICATED:
      status = 401; // Unauthorized
      break;
    case ErrorCode.AUTH_USER_BANNED:
    case ErrorCode.AUTH_USER_LOCKED:
      status = 403; // Forbidden
      break;
    case ErrorCode.RATE_LIMIT_EXCEEDED:
      status = 429; // Too Many Requests
      break;
    case ErrorCode.SERVER_ERROR:
      status = 500; // Internal Server Error
      break;
  }

  // Combine headers
  const responseHeaders = {
    ...securityHeaders,
    "Content-Type": "application/json",
    ...headers,
  };

  // Add cookies if provided
  if (cookies.length > 0) {
    responseHeaders["Set-Cookie"] = cookies.join(", ");
  }

  // Format body
  const body: ApiResponse<null> = {
    success: false,
    data: null,
    error: {
      code: error.code,
      message: error.message,
      details: error.details,
    },
  };

  return {
    status,
    headers: responseHeaders,
    body,
  };
}

/**
 * Formats any response (success or error) with standard structure
 *
 * @param response - AegisResponse from an operation
 * @param options - Response options (headers, cookies, status)
 * @returns Formatted response object
 */
export function formatResponse<T>(
  response: AegisResponse<T>,
  options: ResponseOptions = {},
): {
  status: number;
  headers: Record<string, string>;
  body: ApiResponse<T>;
} {
  if (response.success) {
    return formatSuccessResponse(response.data, options);
  }

  return formatErrorResponse(response.error, options);
}
