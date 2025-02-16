import { z } from "zod";
import {
  type ActionResponse,
  type CoreContext,
  ErrorCodes,
  type PrismaUser,
} from "../types";
import { limitIpAddress } from "../utils";
import { useVerificationTokenCore } from "./useVerificationTokenCore";

const schema = z.object({
  token: z.string().min(1),
});

export async function completeEmailChangeCore(
  ctx: CoreContext,
  options: {
    token: string;
  },
): Promise<ActionResponse> {
  const { parsedRequest, prisma, config, endpoints } = ctx;
  const { logger } = config;
  const { ipAddress } = parsedRequest ?? {};

  logger?.info("completeEmailChangeCore called", {
    ip: ipAddress,
  });

  try {
    const validatedInput = schema.safeParse(options);
    if (!validatedInput.success) {
      logger?.warn("completeEmailChangeCore invalid input", {
        errors: validatedInput.error.errors,
      });
      return {
        success: false,
        status: 400,
        message: "Invalid input provided",
        code: ErrorCodes.INVALID_INPUT,
        data: null,
      };
    }

    const { token } = validatedInput.data;

    if (
      config.protection.rateLimit.endpoints.completeEmailChange.enabled &&
      ipAddress
    ) {
      const limiter = endpoints.completeEmailChange;
      if (!limiter) {
        logger?.error("completeEmailChange rateLimiter not initialized", {
          ip: ipAddress,
        });
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
        logger?.warn("completeEmailChange rate limit exceeded", {
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

    const verificationRequest = await useVerificationTokenCore(ctx, {
      token,
      type: "INITIATE_EMAIL_CHANGE",
    });

    if (
      !verificationRequest.success ||
      !verificationRequest.data?.verification
    ) {
      return verificationRequest;
    }

    const { userId } = verificationRequest.data.verification;

    const user = (await prisma.user.findUnique({
      where: { id: userId },
    })) as PrismaUser | null;

    if (!user) {
      logger?.warn("completeEmailChangeCore user not found", {
        userId,
      });
      return {
        success: false,
        status: 404,
        message: "User not found",
        code: ErrorCodes.ACCOUNT_NOT_FOUND,
        data: null,
      };
    }

    if (!user.pendingEmail) {
      logger?.warn("completeEmailChangeCore no pendingEmail set", { userId });
      return {
        success: false,
        status: 400,
        message: "No pending email on account",
        code: ErrorCodes.EMAIL_INVALID,
        data: null,
      };
    }

    await prisma.$transaction([
      prisma.user.update({
        where: { id: userId },
        data: {
          email: user.pendingEmail,
          // TODO: force re-verification:
          // isEmailVerified: false,
          pendingEmail: null,
        },
      }),
      prisma.session.updateMany({
        where: { userId, isRevoked: false },
        data: { isRevoked: true },
      }),
    ]);

    logger?.info("completeEmailChangeCore success", { userId });

    return {
      success: true,
      status: 200,
      message: "Email change completed",
      data: null,
    };
  } catch (error) {
    logger?.error("completeEmailChangeCore error", {
      error: error instanceof Error ? error.message : String(error),
      ip: ipAddress,
    });

    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred while completing email change",
      code: ErrorCodes.INTERNAL_ERROR,
      data: null,
    };
  }
}
