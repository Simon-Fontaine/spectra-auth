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
 * Properly handles and logs an operation error
 *
 * @param error - The caught error
 * @param logger - Optional logger instance
 * @param errorCode - Error code for the response
 * @param defaultMessage - Default user-facing message
 * @param metadata - Additional metadata for logging
 * @returns A properly formatted error response
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

  // Return a standardized error response
  return fail(
    errorCode,
    defaultMessage,
    // Only include detailed error information in development
    process.env.NODE_ENV !== "production"
      ? { originalError: errorMessage }
      : undefined,
  );
}

/**
 * Creates a tagged operation to simplify error handling patterns
 *
 * @param operationName - Name of the operation for logging
 * @param errorCode - Error code to use if the operation fails
 * @param defaultMessage - Default error message
 * @param logger - Optional logger instance
 * @returns A function wrapper with standardized error handling
 */
export function createOperation<T, P extends unknown[]>(
  operationName: string,
  errorCode: ErrorCodeType,
  defaultMessage: string,
  logger?: LoggerConfig,
) {
  return (operation: (...args: P) => Promise<AegisResponse<T>>) => {
    return async (...args: P): Promise<AegisResponse<T>> => {
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
    };
  };
}

/**
 * Asserts a condition, throwing an error if the condition is false
 *
 * @param condition - Condition to assert
 * @param message - Error message if assertion fails
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
