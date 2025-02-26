import type { ErrorCodeType } from "../constants";
import type { AegisResponse, LoggerConfig } from "../types";
import { fail } from "./response";

/**
 * Error metadata for logging
 */
interface ErrorMetadata {
  requestId?: string;
  userId?: string;
  ipAddress?: string;
  [key: string]: unknown;
}

/**
 * Sanitizes error details to prevent sensitive information leakage
 */
function sanitizeErrorDetails(
  error: unknown,
  logger?: LoggerConfig,
): Record<string, unknown> | undefined {
  // No details for non-Error objects
  if (!(error instanceof Error)) {
    return undefined;
  }

  // Patterns that might indicate sensitive information
  const sensitivePatterns = [
    /password/i,
    /secret/i,
    /token/i,
    /key/i,
    /credential/i,
    /auth/i,
    /hash/i,
    /salt/i,
    /sign/i,
    /crypt/i,
  ];

  const message = error.message;

  // Check if error message contains sensitive information
  const containsSensitiveInfo = sensitivePatterns.some((pattern) =>
    pattern.test(message),
  );

  // Always log the actual error for debugging
  logger?.debug("Original error details", {
    errorMessage: message,
    errorStack: error.stack,
    errorName: error.name,
  });

  // In production, never return sensitive details
  if (process.env.NODE_ENV === "production") {
    return undefined;
  }

  // In development, sanitize sensitive info
  if (containsSensitiveInfo) {
    return {
      safeMessage: "Error details hidden for security",
      errorType: error.name,
    };
  }

  // For non-sensitive errors in development, provide more details
  return {
    originalError: message,
    errorType: error.name,
    // Only return first few lines of stack for security
    stack: error.stack?.split("\n").slice(0, 3).join("\n"),
  };
}

/**
 * Properly handles and logs an operation error
 */
export function handleError<T>(
  error: unknown,
  logger: LoggerConfig | undefined,
  errorCode: ErrorCodeType,
  defaultMessage: string,
  metadata?: ErrorMetadata,
): AegisResponse<T> {
  // Extract error details
  const isError = error instanceof Error;
  const errorMessage = isError ? error.message : String(error);
  const errorStack = isError ? error.stack : undefined;

  // Log the error with context
  logger?.error(`Operation failed: ${defaultMessage}`, {
    errorCode,
    errorMessage,
    errorStack,
    ...metadata,
  });

  // Return a standardized error response with sanitized details
  return fail(errorCode, defaultMessage, sanitizeErrorDetails(error, logger));
}

/**
 * Creates a tagged operation to simplify error handling patterns
 */
export function createOperation<T>(
  operationName: string,
  errorCode: ErrorCodeType,
  defaultMessage: string,
  logger?: LoggerConfig,
) {
  return <Fn extends (...args: never[]) => Promise<AegisResponse<T>>>(
    operation: Fn,
  ): Fn => {
    return (async (...args: Parameters<Fn>): Promise<AegisResponse<T>> => {
      try {
        logger?.debug(`${operationName} operation started`, {
          timestamp: new Date().toISOString(),
        });

        const result = await operation(...args);

        if (result.success) {
          logger?.debug(`${operationName} operation completed successfully`, {
            timestamp: new Date().toISOString(),
          });
        } else {
          logger?.warn(`${operationName} operation failed with error`, {
            errorCode: result.error.code,
            errorMessage: result.error.message,
            timestamp: new Date().toISOString(),
          });
        }

        return result;
      } catch (error) {
        return handleError(error, logger, errorCode, defaultMessage, {
          operationName,
        });
      }
    }) as Fn;
  };
}

/**
 * Asserts a condition, throwing an error if the condition is false
 */
export function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

/**
 * Custom error class for authentication errors
 */
export class AuthError extends Error {
  readonly code: ErrorCodeType;

  constructor(code: ErrorCodeType, message: string) {
    super(message);
    this.name = "AuthError";
    this.code = code;

    // Properly maintain the prototype chain
    Object.setPrototypeOf(this, AuthError.prototype);
  }
}
