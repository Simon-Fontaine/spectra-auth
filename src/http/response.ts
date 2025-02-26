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
 * Type for response return object
 */
type FormattedResponse<T> = {
  status: number;
  headers: Record<string, string>;
  body: ApiResponse<T>;
};

/**
 * Builds response headers with security headers and custom headers
 *
 * @param customHeaders - Additional headers to include
 * @param cookies - Cookies to set
 * @returns Combined headers object
 */
function buildResponseHeaders(
  customHeaders: Record<string, string> = {},
  cookies?: string[],
): Record<string, string> {
  const responseHeaders: Record<string, string> = {
    ...securityHeaders,
    "Content-Type": "application/json",
    ...customHeaders,
  };

  // Add cookies if provided
  if (cookies && cookies.length > 0) {
    responseHeaders["Set-Cookie"] = cookies.join(", ");
  }

  return responseHeaders;
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
): FormattedResponse<T> {
  const { headers = {}, cookies = [], status = 200 } = options;

  return {
    status,
    headers: buildResponseHeaders(headers, cookies),
    body: {
      success: true,
      data,
    },
  };
}

/**
 * Formats an error response with standard structure
 *
 * @param error - Error object
 * @param options - Response options (headers, cookies, status)
 * @returns Formatted response object
 */
export function formatErrorResponse<T = null>(
  error: AegisError,
  options: ResponseOptions = {},
): FormattedResponse<T> {
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

  return {
    status,
    headers: buildResponseHeaders(headers, cookies),
    body: {
      success: false,
      data: null as unknown as T, // Type assertion to make it compatible
      error: {
        code: error.code,
        message: error.message,
        details: error.details,
      },
    },
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
): FormattedResponse<T> {
  if (response.success) {
    return formatSuccessResponse(response.data, options);
  }

  return formatErrorResponse<T>(response.error, options);
}
