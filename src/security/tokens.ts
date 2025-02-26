import { ErrorCode, Security } from "../constants";
import type {
  AegisAuthConfig,
  AegisResponse,
  CsrfToken,
  SessionToken,
  VerificationToken,
} from "../types";
import { createOperation } from "../utils/error";
import { fail, success } from "../utils/response";
import { createHmac, encodeBase64, generateRandomBytes } from "./crypto";

/**
 * Generates a secure random session token
 */
export const generateSessionToken = createOperation(
  "generateSessionToken",
  ErrorCode.SESSION_TOKEN_ERROR,
  "Failed to generate session token",
)(
  async (
    config: AegisAuthConfig,
  ): Promise<AegisResponse<{ token: SessionToken; hash: string }>> => {
    // Generate secure random bytes for the token
    const bytesResponse = generateRandomBytes(
      config.session.tokenLength || Security.DEFAULT_SESSION_TOKEN_LENGTH,
    );

    if (!bytesResponse.success) {
      return bytesResponse;
    }

    // Convert to URL-safe base64 string
    const token = encodeBase64(bytesResponse.data, true) as SessionToken;

    // Create HMAC of the token using the session secret
    const hashResponse = await createHmac(
      "SHA-256",
      config.session.secret,
      token,
      "base64url",
    );

    if (!hashResponse.success) {
      return fail(ErrorCode.SESSION_TOKEN_ERROR, "Failed to create token hash");
    }

    return success({
      token,
      hash: hashResponse.data,
    });
  },
);

/**
 * Verifies a session token against its hash
 */
export const verifySessionToken = createOperation(
  "verifySessionToken",
  ErrorCode.SESSION_TOKEN_ERROR,
  "Failed to verify session token",
)(
  async (
    token: string,
    hash: string,
    config: AegisAuthConfig,
  ): Promise<AegisResponse<boolean>> => {
    // Create HMAC of the token using the session secret
    const hashResponse = await createHmac(
      "SHA-256",
      config.session.secret,
      token,
      "base64url",
    );

    if (!hashResponse.success) {
      return hashResponse;
    }

    // Compare the calculated hash with the stored hash
    const isValid = hashResponse.data === hash;

    return success(isValid);
  },
);

/**
 * Generates a secure random CSRF token
 */
export const generateCsrfToken = createOperation(
  "generateCsrfToken",
  ErrorCode.CSRF_INVALID,
  "Failed to generate CSRF token",
)(
  async (
    config: AegisAuthConfig,
  ): Promise<AegisResponse<{ token: CsrfToken; hash: string }>> => {
    // Generate secure random bytes for the token
    const bytesResponse = generateRandomBytes(
      config.csrf.tokenLength || Security.DEFAULT_TOKEN_LENGTH,
    );

    if (!bytesResponse.success) {
      return bytesResponse;
    }

    // Convert to URL-safe base64 string
    const token = encodeBase64(bytesResponse.data, true) as CsrfToken;

    // Create HMAC of the token using the CSRF secret
    const hashResponse = await createHmac(
      "SHA-256",
      config.csrf.secret,
      token,
      "base64url",
    );

    if (!hashResponse.success) {
      return fail(ErrorCode.CSRF_INVALID, "Failed to create token hash");
    }

    return success({
      token,
      hash: hashResponse.data,
    });
  },
);

/**
 * Verifies a CSRF token against its hash
 */
export const verifyCsrfToken = createOperation(
  "verifyCsrfToken",
  ErrorCode.CSRF_INVALID,
  "Failed to verify CSRF token",
)(
  async (
    token: string,
    hash: string,
    config: AegisAuthConfig,
  ): Promise<AegisResponse<boolean>> => {
    // Create HMAC of the token using the CSRF secret
    const hashResponse = await createHmac(
      "SHA-256",
      config.csrf.secret,
      token,
      "base64url",
    );

    if (!hashResponse.success) {
      return hashResponse;
    }

    // Compare the calculated hash with the stored hash
    const isValid = hashResponse.data === hash;

    return success(isValid);
  },
);

/**
 * Generates a secure random verification token
 */
export const generateVerificationToken = createOperation(
  "generateVerificationToken",
  ErrorCode.VERIFICATION_INVALID,
  "Failed to generate verification token",
)(
  async (
    config: AegisAuthConfig,
  ): Promise<AegisResponse<VerificationToken>> => {
    // Generate secure random bytes for the token
    const bytesResponse = generateRandomBytes(
      config.verification.tokenLength || Security.DEFAULT_TOKEN_LENGTH,
    );

    if (!bytesResponse.success) {
      return bytesResponse;
    }

    // Convert to URL-safe base64 string
    const token = encodeBase64(bytesResponse.data, true) as VerificationToken;

    return success(token);
  },
);
