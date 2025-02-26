import type { ErrorCodeType } from "../constants";

/**
 * Standard error object returned by authentication operations
 */
export interface AegisError {
  code: ErrorCodeType;
  message: string;
  details?: Record<string, unknown>;
}

/**
 * Base response type that all operations return
 */
export type AegisResponse<T> =
  | {
      success: true;
      data: T;
      error: null;
      metadata?: Record<string, unknown>;
    }
  | {
      success: false;
      data: null;
      error: AegisError;
      metadata?: Record<string, unknown>;
    };
