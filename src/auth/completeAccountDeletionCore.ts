import { VerificationType } from "@prisma/client";
import type { AegisContext, AegisResponse } from "../types";
import { fail, limitIpAddress, revokeSession, success } from "../utils";
import { useVerificationTokenCore } from "./verifications";

interface AccountDeletionRequest {
  token: string;
}

export async function completeAccountDeletionCore(
  ctx: AegisContext,
  options: AccountDeletionRequest,
): Promise<AegisResponse<boolean>> {
  const { config, prisma, req, auth, endpoints } = ctx;
  const { logger } = config;
  const requestId = Math.random().toString(36).substring(2, 15);

  logger?.debug("completeAccountDeletionCore invoked", {
    requestId,
    token: options.token,
    ipAddress: req.ipAddress,
  });

  try {
    // Apply rate limiting if enabled
    if (
      config.rateLimit.endpoints.completeAccountDeletion?.enabled &&
      req.ipAddress
    ) {
      const limiter = endpoints.completeAccountDeletion;
      if (!limiter) {
        logger?.error(
          "completeAccountDeletionCore missing rate-limit endpoint",
          {
            requestId,
            ipAddress: req.ipAddress,
          },
        );
        return fail(
          "ACCOUNT_DELETION_RATE_LIMIT_ERROR",
          "Server misconfiguration. Please try again later.",
        );
      }

      const limit = await limitIpAddress(req.ipAddress, limiter);
      if (!limit.success) {
        logger?.warn("completeAccountDeletionCore rate limit exceeded", {
          requestId,
          ipAddress: req.ipAddress,
        });
        return fail(
          "ACCOUNT_DELETION_RATE_LIMIT_EXCEEDED",
          "Too many requests. Please try again later.",
        );
      }
    }

    // Verify and consume the verification token
    const verification = await useVerificationTokenCore(ctx, {
      token: options.token,
      type: VerificationType.COMPLETE_ACCOUNT_DELETION,
    });

    if (!verification.success) {
      logger?.warn("completeAccountDeletionCore verification failed", {
        requestId,
        token: options.token,
        error: verification.error.message,
        ipAddress: req.ipAddress,
      });
      return fail(
        "ACCOUNT_DELETION_VERIFICATION_FAILED",
        "Invalid or expired verification token.",
      );
    }

    const userId = verification.data.userId;

    // Revoke current session if exists
    if (auth.session) {
      await revokeSession(prisma, auth.session.id);
    }

    // Revoke all user sessions
    await prisma.session.updateMany({
      where: { userId, isRevoked: false },
      data: { isRevoked: true },
    });

    logger?.info("completeAccountDeletionCore all sessions revoked", {
      requestId,
      userId,
      ipAddress: req.ipAddress,
    });

    // Use a transaction to ensure atomic deletion of all related records
    await prisma.$transaction(async (tx) => {
      // Delete all related records first (foreign key dependencies)
      await tx.verification.deleteMany({ where: { userId } });
      await tx.passwordHistory.deleteMany({ where: { userId } });
      await tx.userRoles.deleteMany({ where: { userId } });
      await tx.session.deleteMany({ where: { userId } });

      // Finally delete the user
      await tx.user.delete({ where: { id: userId } });
    });

    logger?.info("completeAccountDeletionCore account deleted", {
      requestId,
      userId,
      ipAddress: req.ipAddress,
    });

    return success(true);
  } catch (error) {
    logger?.error("completeAccountDeletionCore unexpected failure", {
      requestId,
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
      ipAddress: req.ipAddress,
    });
    return fail(
      "ACCOUNT_DELETION_ERROR",
      "Failed to delete account. Please try again.",
    );
  }
}
