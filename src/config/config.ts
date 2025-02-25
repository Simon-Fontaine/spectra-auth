import { merge } from "lodash";
import type { AegisAuthConfig } from "../types";
import type { AegisResponse } from "../types";
import { fail, success } from "../utils/response";
import {
  defaultAccountConfig,
  defaultCoreConfig,
  defaultCsrfConfig,
  defaultEmailConfig,
  defaultGeoLookupConfig,
  defaultIPDetectionOptions,
  defaultLoginConfig,
  defaultPasswordConfig,
  defaultRateLimitConfig,
  defaultRegistrationConfig,
  defaultSessionConfig,
  defaultVerificationConfig,
} from "./defaults";

export function buildConfig(
  userConfig: Partial<AegisAuthConfig>,
): AegisResponse<AegisAuthConfig> {
  try {
    const defaultConfig: AegisAuthConfig = {
      core: defaultCoreConfig,
      account: defaultAccountConfig,
      registration: defaultRegistrationConfig,
      login: defaultLoginConfig,
      password: defaultPasswordConfig,
      session: defaultSessionConfig,
      csrf: defaultCsrfConfig,
      verification: defaultVerificationConfig,
      rateLimit: defaultRateLimitConfig,
      geoLookup: defaultGeoLookupConfig,
      email: defaultEmailConfig,
      ipDetection: defaultIPDetectionOptions,
    };

    const mergedConfig = merge({}, defaultConfig, userConfig);

    if (mergedConfig.session.secret === "CHANGE_THIS_DEFAULT_SECRET") {
      return fail(
        "SESSION_SECRET_ERROR",
        "AegisAuth: session.secret MUST be set to a strong, random value.",
      );
    }
    if (
      mergedConfig.csrf.enabled &&
      mergedConfig.csrf.secret === "CHANGE_THIS_DEFAULT_SECRET"
    ) {
      return fail(
        "CSRF_SECRET_ERROR",
        "AegisAuth: csrf.secret MUST be set to a strong, random value when CSRF protection is enabled.",
      );
    }

    if (!mergedConfig.email.sendEmailVerification) {
      return fail(
        "EMAIL_VERIFICATION_HANDLER_ERROR",
        "AegisAuth: email.sendEmailVerification function must be provided.",
      );
    }
    if (!mergedConfig.email.sendPasswordReset) {
      return fail(
        "EMAIL_RESET_HANDLER_ERROR",
        "AegisAuth: email.sendPasswordReset function must be provided.",
      );
    }
    if (!mergedConfig.email.sendEmailChange) {
      return fail(
        "EMAIL_CHANGE_HANDLER_ERROR",
        "AegisAuth: email.sendEmailChange function must be provided.",
      );
    }
    if (!mergedConfig.email.sendAccountDeletion) {
      return fail(
        "EMAIL_DELETION_HANDLER_ERROR",
        "AegisAuth: email.sendAccountDeletion function must be provided.",
      );
    }

    return success(mergedConfig as AegisAuthConfig);
  } catch (error) {
    return fail("CONFIG_BUILD_ERROR", (error as Error).message);
  }
}
