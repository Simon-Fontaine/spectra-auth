import { ErrorCode } from "../constants";
import type { AegisAuthConfig, AegisResponse } from "../types";
import { fail, success } from "../utils/response";

/**
 * Validates the configuration for required fields and proper values
 */
export function validateConfig(config: AegisAuthConfig): AegisResponse<true> {
  // Validate session secret in production
  if (config.core.environment === "production") {
    if (!process.env.SESSION_TOKEN_SECRET) {
      return fail(
        ErrorCode.CONFIG_ERROR,
        "SESSION_TOKEN_SECRET environment variable must be set in production",
      );
    }

    // Validate CSRF secret if enabled
    if (config.csrf.enabled && !process.env.CSRF_TOKEN_SECRET) {
      return fail(
        ErrorCode.CONFIG_ERROR,
        "CSRF_TOKEN_SECRET environment variable must be set in production when CSRF is enabled",
      );
    }
  }

  // Validate rate limiting configuration if enabled
  if (config.rateLimit.enabled && !config.rateLimit.redis) {
    return fail(
      ErrorCode.CONFIG_ERROR,
      "Redis instance must be provided when rate limiting is enabled",
    );
  }

  // Validate email handlers
  if (
    config.account.requireEmailVerification &&
    !config.email.sendEmailVerification
  ) {
    return fail(
      ErrorCode.CONFIG_ERROR,
      "Email verification handler must be provided when email verification is required",
    );
  }

  if (!config.email.sendPasswordReset) {
    return fail(
      ErrorCode.CONFIG_ERROR,
      "Password reset email handler must be provided",
    );
  }

  if (!config.email.sendEmailChange) {
    return fail(
      ErrorCode.CONFIG_ERROR,
      "Email change handler must be provided",
    );
  }

  if (!config.email.sendAccountDeletion) {
    return fail(
      ErrorCode.CONFIG_ERROR,
      "Account deletion handler must be provided",
    );
  }

  // Validate geolocation service if enabled
  if (config.geoLookup.enabled) {
    if (
      !config.geoLookup.maxmindClientId ||
      !config.geoLookup.maxmindLicenseKey
    ) {
      return fail(
        ErrorCode.CONFIG_ERROR,
        "MaxMind client ID and license key must be provided when geolocation is enabled",
      );
    }
  }

  // Check for nonsensical values
  if (config.session.absoluteMaxLifetimeSeconds <= 0) {
    return fail(
      ErrorCode.CONFIG_ERROR,
      "Session lifetime must be greater than zero",
    );
  }

  if (config.session.refreshIntervalSeconds <= 0) {
    return fail(
      ErrorCode.CONFIG_ERROR,
      "Session refresh interval must be greater than zero",
    );
  }

  if (config.verification.tokenExpirySeconds <= 0) {
    return fail(
      ErrorCode.CONFIG_ERROR,
      "Verification token expiry must be greater than zero",
    );
  }

  // Password configuration validation
  const minLength = config.password.rules.minLength;
  if (minLength < 8) {
    return fail(
      ErrorCode.CONFIG_ERROR,
      "Password minimum length should be at least 8 characters for security",
    );
  }

  return success(true);
}
