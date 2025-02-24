import { VerificationType } from "@prisma/client";
import type { AegisContext, AegisResponse } from "../types";
import { fail, limitIpAddress, success } from "../utils";
import { createVerificationCore } from "./verifications";

export async function initiateAccountDeletionCore(
  ctx: AegisContext,
): Promise<AegisResponse<boolean>> {
  const { config, req, auth, endpoints } = ctx;
  const { logger } = config;

  logger?.debug("initiateAccountDeletionCore invoked", {
    userId: auth.user?.id,
    email: auth.user?.email,
    ipAddress: req.ipAddress,
  });

  try {
    if (
      config.rateLimit.endpoints.initiateAccountDeletion?.enabled &&
      req.ipAddress
    ) {
      const limiter = endpoints.initiateAccountDeletion;
      if (!limiter) {
        logger?.error(
          "initiateAccountDeletionCore missing rate-limit endpoint",
          {
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
        logger?.warn("initiateAccountDeletionCore rate limit exceeded", {
          ipAddress: req.ipAddress,
        });
        return fail(
          "ACCOUNT_DELETION_RATE_LIMIT_EXCEEDED",
          "Too many requests. Please try again later.",
        );
      }
    }

    if (!auth.isAuthenticated || !auth.user) {
      logger?.warn("initiateAccountDeletionCore user not authenticated", {
        ipAddress: req.ipAddress,
      });
      return fail(
        "ACCOUNT_DELETION_UNAUTHENTICATED",
        "You must be logged in to delete your account.",
      );
    }

    const verificationResp = await createVerificationCore(ctx, {
      userId: auth.user.id,
      type: VerificationType.COMPLETE_ACCOUNT_DELETION,
    });
    if (!verificationResp.success) {
      logger?.error(
        "initiateAccountDeletionCore verification creation failed",
        {
          userId: auth.user.id,
          ipAddress: req.ipAddress,
          error: verificationResp.error.message,
        },
      );
      return fail(
        "ACCOUNT_DELETION_VERIFICATION_ERROR",
        "Failed to generate account deletion token. Please try again.",
      );
    }

    const { token } = verificationResp.data;
    await config.email.sendAccountDeletion({
      ctx,
      to: auth.user.email,
      token,
    });

    logger?.info("initiateAccountDeletionCore verification created", {
      userId: auth.user.id,
      ipAddress: req.ipAddress,
    });

    return success(true);
  } catch (error) {
    logger?.error("initiateAccountDeletionCore unexpected failure", {
      error: error instanceof Error ? error.message : String(error),
      ipAddress: req.ipAddress,
    });
    return fail(
      "ACCOUNT_DELETION_ERROR",
      "Failed to initiate account deletion. Please try again.",
    );
  }
}
