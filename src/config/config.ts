import { merge } from "lodash";
import type { AegisAuthConfig } from "../types";
import {
  defaultAccountConfig,
  defaultCoreConfig,
  defaultCsrfConfig,
  defaultEmailConfig,
  defaultGeoLookupConfig,
  defaultLoginConfig,
  defaultPasswordConfig,
  defaultRateLimitConfig,
  defaultRegistrationConfig,
  defaultSessionConfig,
  defaultVerificationConfig,
} from "./defaults";

export function buildConfig(
  userConfig: Partial<AegisAuthConfig>,
): AegisAuthConfig {
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
  };

  const mergedConfig = merge({}, defaultConfig, userConfig);

  if (mergedConfig.session.secret === "CHANGE_THIS_DEFAULT_SECRET") {
    throw new Error(
      "AegisAuth: session.secret MUST be set to a strong, random value.",
    );
  }
  if (
    mergedConfig.csrf.enabled &&
    mergedConfig.csrf.secret === "CHANGE_THIS_DEFAULT_SECRET"
  ) {
    throw new Error(
      "AegisAuth: csrf.secret MUST be set to a strong, random value when CSRF protection is enabled.",
    );
  }

  if (!mergedConfig.email.sendEmailVerification) {
    throw new Error(
      "AegisAuth: email.sendEmailVerification function must be provided.",
    );
  }
  if (!mergedConfig.email.sendPasswordReset) {
    throw new Error(
      "AegisAuth: email.sendPasswordReset function must be provided.",
    );
  }
  if (!mergedConfig.email.sendEmailChange) {
    throw new Error(
      "AegisAuth: email.sendEmailChange function must be provided.",
    );
  }
  if (!mergedConfig.email.sendAccountDeletion) {
    throw new Error(
      "AegisAuth: email.sendAccountDeletion function must be provided.",
    );
  }

  return mergedConfig as AegisAuthConfig;
}
