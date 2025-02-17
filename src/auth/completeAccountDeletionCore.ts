import { z } from "zod";
import { type ActionResponse, type CoreContext, ErrorCodes } from "../types";
import { limitIpAddress } from "../utils";
import { useVerificationTokenCore } from "./useVerificationTokenCore";

const schema = z.object({
  token: z.string().min(1),
});

export async function completeAccountDeletionCore(
  ctx: CoreContext,
  options: { token: string },
): Promise<ActionResponse> {
  const { parsedRequest, prisma, config, endpoints } = ctx;
  const { logger } = config;
  const { ipAddress } = parsedRequest ?? {};

  logger?.info("completeAccountDeletionCore called", {
    ip: ipAddress,
  });

  try {
    const parsed = schema.safeParse(options);
    if (!parsed.success) {
      logger?.warn("completeAccountDeletionCore invalid input", {
        errors: parsed.error.errors,
      });
      return {
        success: false,
        status: 400,
        message: "Invalid input provided",
        code: ErrorCodes.INVALID_INPUT,
        data: null,
      };
    }

    const { token } = parsed.data;

    if (
      config.protection.rateLimit.endpoints.completeAccountDeletion?.enabled &&
      ipAddress
    ) {
      const limiter = endpoints.completeAccountDeletion;
      if (!limiter) {
        logger?.error(
          "completeAccountDeletionCore rateLimiter not initialized",
          {
            ip: ipAddress,
          },
        );
        return {
          success: false,
          status: 500,
          message: "Rate limiter not initialized",
          code: ErrorCodes.INTERNAL_ERROR,
          data: null,
        };
      }

      const limit = await limitIpAddress(ipAddress, limiter);
      if (!limit.success) {
        logger?.warn("completeAccountDeletionCore rate limit exceeded", {
          ip: ipAddress,
        });
        return {
          success: false,
          status: 429,
          message: "Too many requests. Try again later.",
          code: ErrorCodes.RATE_LIMIT_EXCEEDED,
          data: null,
        };
      }
    }

    const verificationResult = await useVerificationTokenCore(ctx, {
      token,
      type: "INITIATE_ACCOUNT_DELETION",
    });

    if (!verificationResult.success || !verificationResult.data?.verification) {
      logger?.warn("completeAccountDeletionCore verification failed", {
        token,
        reason: verificationResult.message,
      });
      return verificationResult;
    }

    const { userId } = verificationResult.data.verification;

    await prisma.$transaction([
      prisma.session.updateMany({
        where: { userId, isRevoked: false },
        data: { isRevoked: true },
      }),
      prisma.user.delete({
        where: { id: userId },
      }),
    ]);

    logger?.info("completeAccountDeletionCore success", {
      userId,
      ip: ipAddress,
    });

    return {
      success: true,
      status: 200,
      message: "Account deleted successfully",
      data: null,
    };
  } catch (error) {
    logger?.error("completeAccountDeletionCore error", {
      error: error instanceof Error ? error.message : String(error),
      ip: ipAddress,
    });

    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred while completing account deletion",
      code: ErrorCodes.INTERNAL_ERROR,
      data: null,
    };
  }
}
