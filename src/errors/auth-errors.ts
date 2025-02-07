/**
 * Custom error class for rate limiting related errors.
 */
export class RateLimitError extends Error {
  status: number;
  code: string;

  constructor(
    message = "Rate limit exceeded.",
    status = 429,
    code = "E_RATE_LIMIT",
  ) {
    super(message);
    this.name = "RateLimitError";
    this.status = status;
    this.code = code;
    Object.setPrototypeOf(this, RateLimitError.prototype); // Recommended for custom error classes in TS
  }
}

/**
 * Custom error class for CSRF validation failures.
 */
export class CSRFValidationError extends Error {
  status: number;
  code: string;

  constructor(
    message = "CSRF validation failed.",
    status = 403,
    code = "E_CSRF_VALIDATION",
  ) {
    super(message);
    this.name = "CSRFValidationError";
    this.status = status;
    this.code = code;
    Object.setPrototypeOf(this, CSRFValidationError.prototype);
  }
}

/**
 * Custom error class for authentication failures (e.g., invalid credentials).
 */
export class AuthenticationError extends Error {
  status: number;
  code: string;

  constructor(
    message = "Authentication failed.",
    status = 401,
    code = "E_AUTH_FAILED",
  ) {
    super(message);
    this.name = "AuthenticationError";
    this.status = status;
    this.code = code;
    Object.setPrototypeOf(this, AuthenticationError.prototype);
  }
}

/**
 * Custom error class for account lockout.
 */
export class AccountLockedError extends Error {
  status: number;
  code: string;

  constructor(
    message = "Account is locked.",
    status = 423,
    code = "E_ACCOUNT_LOCKED",
  ) {
    super(message);
    this.name = "AccountLockedError";
    this.status = status;
    this.code = code;
    Object.setPrototypeOf(this, AccountLockedError.prototype);
  }
}

/**
 * Custom error class for email verification issues.
 */
export class EmailNotVerifiedError extends Error {
  status: number;
  code: string;

  constructor(
    message = "Email not verified.",
    status = 403,
    code = "E_EMAIL_NOT_VERIFIED",
  ) {
    super(message);
    this.name = "EmailNotVerifiedError";
    this.status = status;
    this.code = code;
    Object.setPrototypeOf(this, EmailNotVerifiedError.prototype);
  }
}

// Add more custom error classes as needed (e.g., for configuration errors, session errors, etc.)
