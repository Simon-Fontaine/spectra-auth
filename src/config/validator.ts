import { ErrorCode } from "../constants";
import type { AegisAuthConfig, AegisResponse } from "../types";
import { fail, success } from "../utils/response";

/**
 * Validates the configuration for required fields and proper values
 *
 * @param config - Authentication configuration to validate
 * @returns Response with validation result
 */
export function validateConfig(config: AegisAuthConfig): AegisResponse<true> {
  // Validate session secret
  if (config.session.secret === "CHANGE_THIS_DEFAULT_SECRET") {
    return fail(
      ErrorCode.CONFIG_ERROR,
      "Session secret must be changed from the default value",
    );
  }

  // Validate CSRF secret if enabled
  if (
    config.csrf.enabled &&
    config.csrf.secret === "CHANGE_THIS_DEFAULT_SECRET"
  ) {
    return fail(
      ErrorCode.CONFIG_ERROR,
      "CSRF secret must be changed from the default value when CSRF is enabled",
    );
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

  return success(true);
}
