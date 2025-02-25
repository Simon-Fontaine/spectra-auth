import { scryptAsync } from "@noble/hashes/scrypt";
import { getRandomValues } from "uncrypto";
import type { AegisAuthConfig, AegisResponse } from "../types";
import { fail, success } from "../utils/response";
import { timingSafeEqual } from "./compare";
import { decodeHexToBytes, hex } from "./hex";

/**
 * Generates a secure key from a password using the scrypt algorithm
 *
 * @param password - The user's plain-text password
 * @param salt - Cryptographic salt for the key derivation
 * @param config - Application configuration with scrypt parameters
 * @returns A response with the derived key or an error
 */
async function generateKey({
  password,
  salt,
  config,
}: {
  password: string;
  salt: string;
  config: AegisAuthConfig;
}): Promise<AegisResponse<Uint8Array>> {
  const { cost, blockSize, parallelization, keyLength } = config.password.hash;

  try {
    // Convert password to normalized Unicode form for consistent hashing
    const normalizedPassword = password.normalize("NFKC");

    // Use scrypt algorithm with configured parameters
    const key = await scryptAsync(normalizedPassword, salt, {
      N: cost,
      p: parallelization,
      r: blockSize,
      dkLen: keyLength,
      // Prevent memory exhaustion attacks by setting a maximum memory limit
      maxmem: 128 * cost * blockSize * 2,
    });

    return success(key);
  } catch (error) {
    return fail(
      "PASSWORD_KEY_GENERATION_ERROR",
      "Failed to generate password key",
    );
  }
}

/**
 * Hashes a password for secure storage
 *
 * @param password - The user's plain-text password
 * @param config - Application configuration with password settings
 * @returns A response with the password hash string or an error
 */
export const hashPassword = async ({
  password,
  config,
}: {
  password: string;
  config: AegisAuthConfig;
}): Promise<AegisResponse<string>> => {
  try {
    // Generate a cryptographically secure random salt
    const saltBytes = getRandomValues(new Uint8Array(16));
    const salt = hex.encode(saltBytes);

    // Generate the key using our salt and password
    const keyResponse = await generateKey({ password, salt, config });

    if (!keyResponse.success) {
      return fail("PASSWORD_KEY_GENERATION_ERROR", keyResponse.error.message);
    }

    // Format the final hash as 'salt:derivedKey' in hex encoding
    return success(`${salt}:${hex.encode(keyResponse.data)}`);
  } catch (error) {
    return fail(
      "PASSWORD_HASH_ERROR",
      `Failed to hash password: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
};

/**
 * Verifies a password against a stored hash
 *
 * @param hash - The stored password hash
 * @param password - The password to verify
 * @param config - Application configuration with password settings
 * @returns A response with a boolean indicating if the password is valid
 */
export const verifyPassword = async ({
  hash,
  password,
  config,
}: {
  hash: string;
  password: string;
  config: AegisAuthConfig;
}): Promise<AegisResponse<boolean>> => {
  try {
    // Split the stored hash into salt and key components
    const [salt, key] = hash.split(":");
    if (!salt || !key) {
      return fail(
        "PASSWORD_VERIFICATION_ERROR",
        "Invalid password hash format",
      );
    }

    // Generate a new key using the same salt and the provided password
    const targetKeyResponse = await generateKey({ password, salt, config });

    if (!targetKeyResponse.success) {
      return fail(
        "PASSWORD_KEY_GENERATION_ERROR",
        targetKeyResponse.error.message,
      );
    }

    // Convert the stored key from hex to bytes
    const keyBytes = decodeHexToBytes(key);

    // Use constant-time comparison to prevent timing attacks
    const isValid = timingSafeEqual(targetKeyResponse.data, keyBytes);

    return success(isValid);
  } catch (error) {
    return fail(
      "PASSWORD_VERIFICATION_ERROR",
      `Failed to verify password: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
};

/**
 * Checks if a password has been used before by this user
 *
 * @param password - The password to check
 * @param passwordHistory - Array of the user's previous password hashes
 * @param config - Application configuration
 * @returns A response with a boolean indicating if the password was previously used
 */
export const isPasswordPreviouslyUsed = async ({
  password,
  passwordHistory,
  config,
}: {
  password: string;
  passwordHistory: { passwordHash: string }[];
  config: AegisAuthConfig;
}): Promise<AegisResponse<boolean>> => {
  try {
    // If password history checking is disabled, return false
    if (!config.account.reuseOldPasswords || passwordHistory.length === 0) {
      return success(false);
    }

    // Check the password against each historical hash
    for (const entry of passwordHistory) {
      const verifyResult = await verifyPassword({
        hash: entry.passwordHash,
        password,
        config,
      });

      if (verifyResult.success && verifyResult.data) {
        return success(true); // Password was previously used
      }
    }

    return success(false); // Password was not previously used
  } catch (error) {
    return fail(
      "PASSWORD_HISTORY_CHECK_ERROR",
      "Failed to check password history",
    );
  }
};
