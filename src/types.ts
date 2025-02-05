/**
 * Standard result returned by most library functions.
 */
export interface SpectraAuthResult {
  /**
   * Indicates if an error occurred.
   */
  error: boolean;

  /**
   * Numeric HTTP-style status code (e.g., 200, 400, 401, 429, etc.).
   */
  status: number;

  /**
   * Human-readable message describing the result.
   */
  message: string;

  /**
   * Optional data returned on success, such as a token, userId, or other fields.
   */
  data?: Record<string, unknown>;
}
