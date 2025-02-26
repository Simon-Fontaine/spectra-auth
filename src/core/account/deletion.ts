import type { Prisma, VerificationType } from "@prisma/client";
import { Endpoints, ErrorCode } from "../../constants";
import { generateVerificationToken } from "../../security/tokens";
import type { AegisContext, AegisResponse } from "../../types";
import { createOperation } from "../../utils/error";
import { withRateLimit } from "../../utils/rate-limit";
import { fail, success } from "../../utils/response";
import { addTime } from "../../utils/time";

/**
 * Initiates account deletion by sending a confirmation email
 */
export const initiateAccountDeletion = createOperation(
  "initiateAccountDeletion",
  ErrorCode.ACCOUNT_DELETION_INVALID,
  "Failed to initiate account deletion",
)(async (ctx: AegisContext): Promise<AegisResponse<boolean>> => {
  return withRateLimit(ctx, Endpoints.INITIATE_ACCOUNT_DELETION, async () => {
    const { config, prisma, auth, req } = ctx;

    // Check if user is authenticated
    if (!auth.isAuthenticated || !auth.user) {
      return fail(
        ErrorCode.AUTH_NOT_AUTHENTICATED,
        "You must be logged in to delete your account",
      );
    }

    // Generate verification token
    const tokenResult = await generateVerificationToken(config);
    if (!tokenResult.success) {
      return tokenResult;
    }

    // Create verification record
    await prisma.verification.create({
      data: {
        userId: auth.user.id,
        token: tokenResult.data,
        type: "COMPLETE_ACCOUNT_DELETION" as VerificationType,
        expiresAt: addTime(
          new Date(),
          config.verification.tokenExpirySeconds,
          "s",
        ),
      },
    });

    // Send verification email
    await config.email.sendAccountDeletion({
      ctx,
      to: auth.user.email,
      token: tokenResult.data,
    });

    ctx.config.logger?.info("Account deletion email sent", {
      userId: auth.user.id,
      email: auth.user.email,
      ipAddress: req.ipAddress,
    });

    return success(true);
  });
});

/**
 * Completes account deletion using a verification token
 */
export const completeAccountDeletion = createOperation(
  "completeAccountDeletion",
  ErrorCode.ACCOUNT_DELETION_INVALID,
  "Failed to delete account",
)(async (ctx: AegisContext, token: string): Promise<AegisResponse<boolean>> => {
  return withRateLimit(ctx, Endpoints.COMPLETE_ACCOUNT_DELETION, async () => {
    const { config, prisma, req } = ctx;

    // Find verification record
    const verification = await prisma.verification.findUnique({
      where: { token },
    });

    // Verify token validity
    if (!verification) {
      return fail(
        ErrorCode.ACCOUNT_DELETION_INVALID,
        "Invalid verification token",
      );
    }

    // Check token type
    if (verification.type !== "COMPLETE_ACCOUNT_DELETION") {
      return fail(
        ErrorCode.VERIFICATION_TYPE_MISMATCH,
        "Invalid verification type",
      );
    }

    // Check if token is expired
    if (verification.expiresAt < new Date()) {
      return fail(
        ErrorCode.ACCOUNT_DELETION_INVALID,
        "Verification token has expired",
      );
    }

    // Check if token is already used
    if (verification.usedAt) {
      return fail(
        ErrorCode.ACCOUNT_DELETION_INVALID,
        "Verification token has already been used",
      );
    }

    const userId = verification.userId;

    // Revoke all sessions
    await prisma.session.updateMany({
      where: {
        userId,
        isRevoked: false,
      },
      data: { isRevoked: true },
    });

    // Delete the account with all related data
    await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
      // Delete related records first to avoid foreign key constraints
      await tx.verification.deleteMany({ where: { userId } });
      await tx.passwordHistory.deleteMany({ where: { userId } });
      await tx.userRoles.deleteMany({ where: { userId } });
      await tx.session.deleteMany({ where: { userId } });

      // Delete the user
      await tx.user.delete({ where: { id: userId } });
    });

    ctx.config.logger?.info("Account deleted successfully", {
      userId,
      ipAddress: req.ipAddress,
    });

    return success(true);
  });
});
