import { sendVerificationEmail } from "../emails/sendVerificationEmail";
import { type ActionResponse, type CoreContext, ErrorCodes } from "../types";
import { limitIpAddress } from "../utils";
import { createVerificationCore } from "./createVerificationCore";
import { getSessionCore } from "./getSessionCore";

export async function initiateAccountDeletionCore(
  ctx: CoreContext,
): Promise<ActionResponse> {
  const { parsedRequest, config, endpoints } = ctx;
  const { logger } = config;
  const { ipAddress } = parsedRequest ?? {};

  logger?.info("initiateAccountDeletionCore called", {
    ip: ipAddress,
  });

  try {
    if (
      config.protection.rateLimit.endpoints.initiateAccountDeletion.enabled &&
      ipAddress
    ) {
      const limiter = endpoints.initiateAccountDeletion;
      if (!limiter) {
        logger?.error(
          "initiateAccountDeletionCore rateLimiter not initialized",
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
        logger?.warn("initiateAccountDeletionCore rate limit exceeded", {
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

    const sessionResult = await getSessionCore(ctx, { disableRefresh: true });
    if (!sessionResult.success || !sessionResult.data) {
      return sessionResult;
    }
    const { session, user } = sessionResult.data;

    if (!session || session.isRevoked) {
      logger?.warn("initiateAccountDeletionCore invalid or revoked session", {
        ip: ipAddress,
      });
      return {
        success: false,
        status: 401,
        message: "Invalid or revoked session token",
        code: ErrorCodes.SESSION_INVALID,
      };
    }
    const userId = session.userId;

    if (!user) {
      logger?.warn("initiateAccountDeletionCore user not found", {
        userId,
        ip: ipAddress,
      });
      return {
        success: false,
        status: 404,
        message: "User not found",
        code: ErrorCodes.ACCOUNT_NOT_FOUND,
        data: null,
      };
    }

    const verificationRequest = await createVerificationCore(ctx, {
      userId,
      type: "INITIATE_ACCOUNT_DELETION",
    });

    if (
      !verificationRequest.success ||
      !verificationRequest.data?.verification
    ) {
      logger?.error("initiateAccountDeletionCore createVerification error", {
        userId,
      });
      return {
        success: false,
        status: 500,
        message:
          "An unexpected error occurred while initiating account deletion",
        code: ErrorCodes.INTERNAL_ERROR,
        data: null,
      };
    }

    const { token } = verificationRequest.data.verification;
    await sendVerificationEmail(ctx, {
      toEmail: user.email,
      token,
      type: "INITIATE_ACCOUNT_DELETION",
    });

    logger?.info("initiateAccountDeletionCore success", {
      userId,
      ip: ipAddress,
    });

    return {
      success: true,
      status: 200,
      message:
        "Account deletion initiated. Please confirm via verification token.",
      data: null,
    };
  } catch (error) {
    logger?.error("initiateAccountDeletionCore error", {
      error: error instanceof Error ? error.message : String(error),
      ip: ipAddress,
    });

    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred while initiating account deletion",
      code: ErrorCodes.INTERNAL_ERROR,
      data: null,
    };
  }
}
