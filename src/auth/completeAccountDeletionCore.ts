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

  logger?.debug("completeAccountDeletionCore invoked", {
    token: options.token,
    ipAddress: req.ipAddress,
  });

  try {
    if (
      config.rateLimit.endpoints.completeAccountDeletion?.enabled &&
      req.ipAddress
    ) {
      const limiter = endpoints.completeAccountDeletion;
      if (!limiter) {
        logger?.error(
          "completeAccountDeletionCore missing rate-limit endpoint",
          { ipAddress: req.ipAddress },
        );
        return fail(
          "ACCOUNT_DELETION_RATE_LIMIT_ERROR",
          "Server misconfiguration. Please try again later.",
        );
      }

      const limit = await limitIpAddress(req.ipAddress, limiter);
      if (!limit.success) {
        logger?.warn("completeAccountDeletionCore rate limit exceeded", {
          ipAddress: req.ipAddress,
        });
        return fail(
          "ACCOUNT_DELETION_RATE_LIMIT_EXCEEDED",
          "Too many requests. Please try again later.",
        );
      }
    }

    const verification = await useVerificationTokenCore(ctx, {
      token: options.token,
      type: VerificationType.COMPLETE_ACCOUNT_DELETION,
    });

    if (!verification.success) {
      logger?.warn("completeAccountDeletionCore verification failed", {
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

    if (auth.session) {
      await revokeSession(prisma, auth.session.id);
    }

    await prisma.session.updateMany({
      where: { userId, isRevoked: false },
      data: { isRevoked: true },
    });

    await prisma.$transaction([
      prisma.verification.deleteMany({ where: { userId } }),
      prisma.passwordHistory.deleteMany({ where: { userId } }),
      prisma.userRoles.deleteMany({ where: { userId } }),
      prisma.session.deleteMany({ where: { userId } }),
      prisma.user.delete({ where: { id: userId } }),
    ]);

    logger?.info("completeAccountDeletionCore account deleted", {
      userId,
      ipAddress: req.ipAddress,
    });

    return success(true);
  } catch (error) {
    logger?.error("completeAccountDeletionCore unexpected failure", {
      error: error instanceof Error ? error.message : String(error),
      ipAddress: req.ipAddress,
    });
    return fail(
      "ACCOUNT_DELETION_ERROR",
      "Failed to delete account. Please try again.",
    );
  }
}
