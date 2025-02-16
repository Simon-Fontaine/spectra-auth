import { signSessionToken } from "../security";
import {
  type ActionResponse,
  type CoreContext,
  ErrorCodes,
  type PrismaSession,
  type PrismaUser,
} from "../types";
import { limitIpAddress } from "../utils";
import { createVerificationCore } from "./createVerificationCore";

export async function initiateAccountDeletionCore(
  ctx: CoreContext,
): Promise<ActionResponse> {
  const { parsedRequest, prisma, config, endpoints } = ctx;
  const { logger } = config;
  const { ipAddress, sessionToken } = parsedRequest ?? {};

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

    if (!sessionToken) {
      logger?.warn("initiateAccountDeletionCore no session token", {
        ip: ipAddress,
      });
      return {
        success: false,
        status: 401,
        message: "No session token provided",
        code: ErrorCodes.SESSION_NOT_FOUND,
      };
    }

    const tokenHash = await signSessionToken({ sessionToken, config });
    const session = (await prisma.session.findUnique({
      where: { tokenHash },
    })) as PrismaSession | null;

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

    const user = (await prisma.user.findUnique({
      where: { id: userId },
    })) as PrismaUser | null;

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
    // TODO: Send email with token
    console.log("Account deletion token:", token);

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
