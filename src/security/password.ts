import { scryptAsync } from "@noble/hashes/scrypt";
import { ErrorCode } from "../constants";
import type { AegisAuthConfig, AegisResponse, PasswordHash } from "../types";
import { handleError } from "../utils/error";
import { fail, success } from "../utils/response";
import {
  decodeHex,
  encodeHex,
  generateRandomBytes,
  timingSafeEqual,
} from "./crypto";

/**
 * Generates a secure password hash using scrypt
 *
 * @param password - Plain text password
 * @param config - Authentication configuration
 * @returns Response with password hash or error
 */
export async function hashPassword(
  password: string,
  config: AegisAuthConfig,
): Promise<AegisResponse<PasswordHash>> {
  try {
    // Generate a random salt
    const saltResponse = generateRandomBytes(16);
    if (!saltResponse.success) {
      return saltResponse;
    }

    const salt = encodeHex(saltResponse.data);

    // Hash parameters from config
    const { cost, blockSize, parallelization, keyLength } =
      config.password.hash;

    // Normalize password for consistent hashing
    const normalizedPassword = password.normalize("NFKC");

    // Use scrypt to derive a key from the password
    const derivedKey = await scryptAsync(normalizedPassword, salt, {
      N: cost,
      r: blockSize,
      p: parallelization,
      dkLen: keyLength,
      // Set reasonable memory limit to prevent DOS attacks
      maxmem: 128 * cost * blockSize * 2,
    });

    // Format as salt:derivedKey
    const hash = `${salt}:${encodeHex(derivedKey)}` as PasswordHash;

    return success(hash);
  } catch (error) {
    return handleError(
      error,
      config.logger,
      ErrorCode.SECURITY_HASH_ERROR,
      "Failed to hash password",
    );
  }
}

/**
 * Verifies a password against a stored hash
 *
 * @param password - Plain text password to verify
 * @param hash - Stored password hash
 * @param config - Authentication configuration
 * @returns Response with verification result
 */
export async function verifyPassword(
  password: string,
  hash: string,
  config: AegisAuthConfig,
): Promise<AegisResponse<boolean>> {
  try {
    // Parse hash components
    const [salt, storedKey] = hash.split(":");

    if (!salt || !storedKey) {
      return fail(
        ErrorCode.SECURITY_HASH_ERROR,
        "Invalid password hash format",
      );
    }

    // Hash parameters from config
    const { cost, blockSize, parallelization, keyLength } =
      config.password.hash;

    // Normalize password for consistent hashing
    const normalizedPassword = password.normalize("NFKC");

    // Derive key using the same salt and parameters
    const derivedKey = await scryptAsync(normalizedPassword, salt, {
      N: cost,
      r: blockSize,
      p: parallelization,
      dkLen: keyLength,
      maxmem: 128 * cost * blockSize * 2,
    });

    // Constant-time comparison to prevent timing attacks
    const isValid = timingSafeEqual(derivedKey, decodeHex(storedKey));

    return success(isValid);
  } catch (error) {
    return handleError(
      error,
      config.logger,
      ErrorCode.SECURITY_HASH_ERROR,
      "Failed to verify password",
    );
  }
}

/**
 * Checks if a password meets the complexity requirements
 *
 * @param password - Password to check
 * @param config - Authentication configuration
 * @returns Response with validation result
 */
export function validatePasswordComplexity(
  password: string,
  config: AegisAuthConfig,
): AegisResponse<boolean> {
  const { rules } = config.password;

  // Check length requirements
  if (password.length < rules.minLength || password.length > rules.maxLength) {
    return fail(
      ErrorCode.PASSWORD_COMPLEXITY,
      `Password must be between ${rules.minLength} and ${rules.maxLength} characters`,
    );
  }

  // Check character requirements
  const hasLowercase = /[a-z]/.test(password);
  const hasUppercase = /[A-Z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSymbol = /[^a-zA-Z0-9]/.test(password);

  const requirements: Array<{ required: boolean; has: boolean; type: string }> =
    [
      {
        required: rules.requireLowercase,
        has: hasLowercase,
        type: "lowercase letter",
      },
      {
        required: rules.requireUppercase,
        has: hasUppercase,
        type: "uppercase letter",
      },
      { required: rules.requireNumber, has: hasNumber, type: "number" },
      { required: rules.requireSymbol, has: hasSymbol, type: "symbol" },
    ];

  const missingRequirements = requirements
    .filter((req) => req.required && !req.has)
    .map((req) => req.type);

  if (missingRequirements.length > 0) {
    return fail(
      ErrorCode.PASSWORD_COMPLEXITY,
      `Password must include at least one ${missingRequirements.join(", ")}`,
    );
  }

  return success(true);
}

/**
 * Checks if a password has been used before
 *
 * @param password - Password to check
 * @param passwordHistory - Array of previous password hashes
 * @param config - Authentication configuration
 * @returns Response with check result
 */
export async function isPasswordPreviouslyUsed(
  password: string,
  passwordHistory: Array<{ passwordHash: string }>,
  config: AegisAuthConfig,
): Promise<AegisResponse<boolean>> {
  try {
    // Skip check if feature is disabled or no history
    if (!config.account.reuseOldPasswords || passwordHistory.length === 0) {
      return success(false);
    }

    // Check against each historical password
    for (const entry of passwordHistory) {
      const result = await verifyPassword(password, entry.passwordHash, config);

      if (result.success && result.data === true) {
        return success(true);
      }
    }

    return success(false);
  } catch (error) {
    return handleError(
      error,
      config.logger,
      ErrorCode.SECURITY_HASH_ERROR,
      "Failed to check password history",
    );
  }
}
