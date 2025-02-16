import { z } from "zod";
import { hashPassword } from "../security";
import {
  type ActionResponse,
  type CoreContext,
  ErrorCodes,
  type PasswordPolicy,
  type PrismaUser,
} from "../types";
import { limitIpAddress } from "../utils";
import { getPasswordSchema } from "../validations";
import { useVerificationTokenCore } from "./useVerificationTokenCore";

const schema = (policy?: PasswordPolicy) =>
  z.object({
    token: z.string().min(1),
    newPassword: getPasswordSchema("Password", policy),
  });

export async function completePasswordResetCore(
  ctx: CoreContext,
  options: {
    token: string;
    newPassword: string;
  },
): Promise<ActionResponse> {
  const { parsedRequest, prisma, config, endpoints } = ctx;
  const { logger } = config;
  const { ipAddress } = parsedRequest ?? {};

  logger?.info("completePasswordResetCore called", {
    ip: ipAddress,
  });

  try {
    const validatedInput = schema(config.auth.password.rules).safeParse(
      options,
    );
    if (!validatedInput.success) {
      logger?.warn("completePasswordResetCore invalid input", {
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

    const { token, newPassword } = validatedInput.data;

    if (
      config.protection.rateLimit.endpoints.completePasswordReset.enabled &&
      ipAddress
    ) {
      const limiter = endpoints.completePasswordReset;
      if (!limiter) {
        logger?.error("completePasswordReset rateLimiter not initialized", {
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
        logger?.warn("completePasswordReset rate limit exceeded", {
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
      type: "INITIATE_PASSWORD_RESET",
    });

    if (
      !verificationRequest.success ||
      !verificationRequest.data?.verification
    ) {
      return verificationRequest;
    }

    const {
      verification: { userId },
    } = verificationRequest.data;

    const user = (await prisma.user.findUnique({
      where: { id: userId },
    })) as PrismaUser | null;

    if (!user) {
      logger?.warn("completePasswordResetCore user not found", {
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

    const newPasswordHash = await hashPassword({
      password: newPassword,
      config,
    });
    await prisma.$transaction([
      prisma.user.update({
        where: { id: userId },
        data: {
          password: newPasswordHash,
        },
      }),
      prisma.session.updateMany({
        where: { userId, isRevoked: false },
        data: {
          isRevoked: true,
        },
      }),
    ]);

    logger?.info("completePasswordResetCore success", {
      userId,
      ip: ipAddress,
    });

    return {
      success: true,
      status: 200,
      message: "Password reset successfully",
      data: null,
    };
  } catch (error) {
    logger?.error("completePasswordResetCore error", {
      error: error instanceof Error ? error.message : String(error),
      ip: ipAddress,
    });

    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred while completing password reset",
      code: ErrorCodes.INTERNAL_ERROR,
      data: null,
    };
  }
}
