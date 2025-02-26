import type { Prisma, VerificationType } from "@prisma/client";
import { z } from "zod";
import { Endpoints, ErrorCode, RegexPatterns } from "../../constants";
import {
  hashPassword,
  isPasswordPreviouslyUsed,
  validatePasswordComplexity,
  verifyPassword,
} from "../../security/password";
import { generateVerificationToken } from "../../security/tokens";
import type { AegisContext, AegisResponse } from "../../types";
import { createOperation } from "../../utils/error";
import { withRateLimit } from "../../utils/rate-limit";
import { fail, success } from "../../utils/response";
import { addTime } from "../../utils/time";

/**
 * Initiates password reset by sending a reset link
 */
export const initiatePasswordReset = createOperation(
  "initiatePasswordReset",
  ErrorCode.PASSWORD_RESET_INVALID,
  "Failed to initiate password reset",
)(async (ctx: AegisContext, email: string): Promise<AegisResponse<boolean>> => {
  return withRateLimit(ctx, Endpoints.INITIATE_PASSWORD_RESET, async () => {
    const { config, prisma, req } = ctx;

    // Validate email format
    if (!email || !RegexPatterns.EMAIL.test(email)) {
      return fail(ErrorCode.PASSWORD_RESET_INVALID, "Invalid email format");
    }

    const normalizedEmail = email.toLowerCase();

    // Find user by email
    const user = await prisma.user.findFirst({
      where: { email: normalizedEmail },
    });

    // For security, don't reveal if email exists or not
    if (!user) {
      ctx.config.logger?.info(
        "Password reset requested for non-existent email",
        {
          email: normalizedEmail,
          ipAddress: req.ipAddress,
        },
      );

      // Return success even though no email will be sent
      // This prevents user enumeration
      return success(true);
    }

    // Check if user is banned
    if (user.isBanned) {
      ctx.config.logger?.warn("Password reset requested for banned user", {
        userId: user.id,
        email: normalizedEmail,
        ipAddress: req.ipAddress,
      });

      // Return success even though no email will be sent
      return success(true);
    }

    // Generate verification token
    const tokenResult = await generateVerificationToken(config);
    if (!tokenResult.success) {
      return tokenResult;
    }

    // Create verification record
    await prisma.verification.create({
      data: {
        userId: user.id,
        token: tokenResult.data,
        type: "COMPLETE_PASSWORD_RESET" as VerificationType,
        expiresAt: addTime(
          new Date(),
          config.verification.tokenExpirySeconds,
          "s",
        ),
      },
    });

    // Send password reset email
    await config.email.sendPasswordReset({
      ctx,
      to: normalizedEmail,
      token: tokenResult.data,
    });

    ctx.config.logger?.info("Password reset email sent", {
      userId: user.id,
      email: normalizedEmail,
      ipAddress: req.ipAddress,
    });

    return success(true);
  });
});

// Schema for password reset completion
const resetPasswordSchema = z.object({
  token: z.string().min(1, "Token is required"),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(64, "Password cannot exceed 64 characters")
    .regex(
      RegexPatterns.PASSWORD_HAS_LOWERCASE,
      "Password must include at least one lowercase letter",
    )
    .regex(
      RegexPatterns.PASSWORD_HAS_UPPERCASE,
      "Password must include at least one uppercase letter",
    )
    .regex(
      RegexPatterns.PASSWORD_HAS_NUMBER,
      "Password must include at least one number",
    )
    .regex(
      RegexPatterns.PASSWORD_HAS_SYMBOL,
      "Password must include at least one special character",
    ),
});

/**
 * Completes password reset using a verification token
 */
export const completePasswordReset = createOperation(
  "completePasswordReset",
  ErrorCode.PASSWORD_RESET_INVALID,
  "Failed to reset password",
)(
  async (
    ctx: AegisContext,
    { token, password }: { token: string; password: string },
  ): Promise<AegisResponse<boolean>> => {
    return withRateLimit(ctx, Endpoints.COMPLETE_PASSWORD_RESET, async () => {
      const { config, prisma, req } = ctx;

      // Validate input
      const parseResult = resetPasswordSchema.safeParse({ token, password });
      if (!parseResult.success) {
        return fail(
          ErrorCode.PASSWORD_RESET_INVALID,
          parseResult.error.errors[0]?.message || "Invalid input",
        );
      }

      // Find verification record
      const verification = await prisma.verification.findUnique({
        where: { token },
        include: {
          user: {
            include: {
              passwordHistory: {
                orderBy: { createdAt: "desc" },
                take: config.account.maxPasswordHistory || 5,
              },
            },
          },
        },
      });

      // Verify token validity
      if (!verification) {
        return fail(
          ErrorCode.PASSWORD_RESET_INVALID,
          "Invalid verification token",
        );
      }

      // Check token type
      if (verification.type !== "COMPLETE_PASSWORD_RESET") {
        return fail(
          ErrorCode.VERIFICATION_TYPE_MISMATCH,
          "Invalid verification type",
        );
      }

      // Check if token is expired
      if (verification.expiresAt < new Date()) {
        return fail(
          ErrorCode.PASSWORD_RESET_EXPIRED,
          "Verification token has expired",
        );
      }

      // Check if token is already used
      if (verification.usedAt) {
        return fail(
          ErrorCode.PASSWORD_RESET_INVALID,
          "Verification token has already been used",
        );
      }

      // Check if the new password is different from current password
      if (verification.user.passwordHash) {
        const isSamePassword = await verifyPassword(
          password,
          verification.user.passwordHash,
          config,
        );

        if (isSamePassword.success && isSamePassword.data) {
          return fail(
            ErrorCode.PASSWORD_PREVIOUSLY_USED,
            "New password cannot be the same as your current password",
          );
        }
      }

      // Check if password was previously used (if configured)
      if (config.account.reuseOldPasswords) {
        const wasUsed = await isPasswordPreviouslyUsed(
          password,
          verification.user.passwordHistory,
          config,
        );

        if (wasUsed.success && wasUsed.data) {
          return fail(
            ErrorCode.PASSWORD_PREVIOUSLY_USED,
            "This password was previously used. Please choose a different password.",
          );
        }
      }

      // Hash the new password
      const passwordHashResult = await hashPassword(password, config);
      if (!passwordHashResult.success) {
        return passwordHashResult;
      }

      // Update user password and save old password in history
      await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
        // Store current password in history if needed
        if (
          config.account.reuseOldPasswords &&
          verification.user.passwordHash
        ) {
          await tx.passwordHistory.create({
            data: {
              userId: verification.userId,
              passwordHash: verification.user.passwordHash,
            },
          });

          // Prune password history if needed
          if (config.account.maxPasswordHistory) {
            const excessEntries =
              verification.user.passwordHistory.length -
              config.account.maxPasswordHistory +
              1;

            if (excessEntries > 0) {
              const oldestEntries = verification.user.passwordHistory
                .slice(-excessEntries)
                .map((entry) => entry.id);

              await tx.passwordHistory.deleteMany({
                where: {
                  id: { in: oldestEntries },
                },
              });
            }
          }
        }

        // Update user password
        await tx.user.update({
          where: { id: verification.userId },
          data: {
            passwordHash: passwordHashResult.data,
            failedLoginAttempts: 0,
            lockedUntil: null,
          },
        });

        // Mark verification as used
        await tx.verification.update({
          where: { id: verification.id },
          data: { usedAt: new Date() },
        });

        // Revoke all existing sessions for security
        await tx.session.updateMany({
          where: {
            userId: verification.userId,
            isRevoked: false,
          },
          data: { isRevoked: true },
        });
      });

      ctx.config.logger?.info("Password reset completed successfully", {
        userId: verification.userId,
        ipAddress: req.ipAddress,
      });

      return success(true);
    });
  },
);

/**
 * Changes password for an authenticated user
 */
export const changePassword = createOperation(
  "changePassword",
  ErrorCode.PASSWORD_COMPLEXITY,
  "Failed to change password",
)(
  async (
    ctx: AegisContext,
    {
      currentPassword,
      newPassword,
    }: { currentPassword: string; newPassword: string },
  ): Promise<AegisResponse<boolean>> => {
    const { config, prisma, auth, req } = ctx;

    // Check if user is authenticated
    if (!auth.isAuthenticated || !auth.user) {
      return fail(
        ErrorCode.AUTH_NOT_AUTHENTICATED,
        "You must be logged in to change your password",
      );
    }

    // Verify current password
    const user = await prisma.user.findUnique({
      where: { id: auth.user.id },
      include: {
        passwordHistory: {
          orderBy: { createdAt: "desc" },
          take: config.account.maxPasswordHistory || 5,
        },
      },
    });

    if (!user) {
      return fail(ErrorCode.AUTH_NOT_AUTHENTICATED, "User not found");
    }

    const passwordValid = await verifyPassword(
      currentPassword,
      user.passwordHash,
      config,
    );

    if (!passwordValid.success || !passwordValid.data) {
      return fail(
        ErrorCode.AUTH_INVALID_CREDENTIALS,
        "Current password is incorrect",
      );
    }

    // Validate new password complexity
    const complexityCheck = validatePasswordComplexity(newPassword, config);
    if (!complexityCheck.success) {
      return complexityCheck;
    }

    // Check if the new password is different from current password
    if (currentPassword === newPassword) {
      return fail(
        ErrorCode.PASSWORD_PREVIOUSLY_USED,
        "New password cannot be the same as your current password",
      );
    }

    // Check if password was previously used
    if (config.account.reuseOldPasswords) {
      const wasUsed = await isPasswordPreviouslyUsed(
        newPassword,
        user.passwordHistory,
        config,
      );

      if (wasUsed.success && wasUsed.data) {
        return fail(
          ErrorCode.PASSWORD_PREVIOUSLY_USED,
          "This password was previously used. Please choose a different password.",
        );
      }
    }

    // Hash the new password
    const passwordHashResult = await hashPassword(newPassword, config);
    if (!passwordHashResult.success) {
      return passwordHashResult;
    }

    // Update user password and save old password in history
    await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
      // Store current password in history if needed
      if (config.account.reuseOldPasswords) {
        await tx.passwordHistory.create({
          data: {
            userId: user.id,
            passwordHash: user.passwordHash,
          },
        });

        // Prune password history if needed
        if (config.account.maxPasswordHistory) {
          const excessEntries =
            user.passwordHistory.length - config.account.maxPasswordHistory + 1;

          if (excessEntries > 0) {
            const oldestEntries = user.passwordHistory
              .slice(-excessEntries)
              .map((entry) => entry.id);

            await tx.passwordHistory.deleteMany({
              where: {
                id: { in: oldestEntries },
              },
            });
          }
        }
      }

      // Update user password
      await tx.user.update({
        where: { id: user.id },
        data: { passwordHash: passwordHashResult.data },
      });
    });

    ctx.config.logger?.info("Password changed successfully", {
      userId: user.id,
      ipAddress: req.ipAddress,
    });

    return success(true);
  },
);
