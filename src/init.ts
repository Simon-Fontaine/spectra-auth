import type { PrismaClient } from "@prisma/client";
import { loginUser } from "./auth/login";
import { logoutUser } from "./auth/logout";
import { registerUser } from "./auth/register";
import {
  completePasswordReset,
  initiatePasswordReset,
} from "./auth/reset-password";
import { createSession, revokeSession, validateSession } from "./auth/session";
import {
  createVerificationToken,
  useVerificationToken,
} from "./auth/verification";

/**
 * Initializes the Spectra Auth library using a user-provided PrismaClient instance.
 *
 * @param prisma - The Prisma client. Must have User, Session, and Verification models.
 * @returns       An object containing all auth methods.
 */
export function initSpectraAuth(prisma: PrismaClient) {
  return {
    // =========== LOGIN / LOGOUT ===========
    loginUser: (options: Parameters<typeof loginUser>[1]) =>
      loginUser(prisma, options),

    logoutUser: (rawToken: Parameters<typeof logoutUser>[1]) =>
      logoutUser(prisma, rawToken),

    // =========== REGISTRATION ===========
    registerUser: (options: Parameters<typeof registerUser>[1]) =>
      registerUser(prisma, options),

    // =========== PASSWORD RESET ===========
    initiatePasswordReset: (
      email: Parameters<typeof initiatePasswordReset>[1],
    ) => initiatePasswordReset(prisma, email),

    completePasswordReset: (
      options: Parameters<typeof completePasswordReset>[1],
    ) => completePasswordReset(prisma, options),

    // =========== SESSIONS ===========
    createSession: (options: Parameters<typeof createSession>[1]) =>
      createSession(prisma, options),

    validateSession: (rawToken: Parameters<typeof validateSession>[1]) =>
      validateSession(prisma, rawToken),

    revokeSession: (rawToken: Parameters<typeof revokeSession>[1]) =>
      revokeSession(prisma, rawToken),

    // =========== VERIFICATION TOKENS ===========
    createVerificationToken: (
      options: Parameters<typeof createVerificationToken>[1],
    ) => createVerificationToken(prisma, options),

    useVerificationToken: (
      options: Parameters<typeof useVerificationToken>[1],
    ) => useVerificationToken(prisma, options),
  };
}
