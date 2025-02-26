import { ErrorCode } from "../constants";
import type { AegisError, AegisResponse } from "../types";
import { securityHeaders } from "./headers";

/**
 * HTTP response formatting utilities.
 * These functions transform internal AegisResponse objects into HTTP-specific
 * responses with appropriate status codes, headers, and body formatting.
 */

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
  cookies?: string[]; // Added to expose cookies for framework-specific handling
};

/**
 * Builds response headers with security headers and custom headers
 * Cookies are now returned separately to be properly handled by frameworks
 */
function buildResponseHeaders(
  customHeaders: Record<string, string> = {},
): Record<string, string> {
  return {
    ...securityHeaders,
    "Content-Type": "application/json",
    ...customHeaders,
  };
}

/**
 * Formats a successful response with standard structure
 */
export function formatSuccessResponse<T>(
  data: T,
  options: ResponseOptions = {},
): FormattedResponse<T> {
  const { headers = {}, cookies = [], status = 200 } = options;

  return {
    status,
    headers: buildResponseHeaders(headers),
    body: {
      success: true,
      data,
    },
    // Return cookies separately for proper multi-header handling
    cookies: cookies.length > 0 ? cookies : undefined,
  };
}

/**
 * Formats an error response with standard structure
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
    headers: buildResponseHeaders(headers),
    body: {
      success: false,
      data: null as unknown as T,
      error: {
        code: error.code,
        message: error.message,
        details: error.details,
      },
    },
    // Return cookies separately for proper multi-header handling
    cookies: cookies.length > 0 ? cookies : undefined,
  };
}

/**
 * Formats any response (success or error) with standard structure
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
