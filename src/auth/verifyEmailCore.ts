import { z } from "zod";
import { type ActionResponse, type CoreContext, ErrorCodes } from "../types";
import { limitIpAddress } from "../utils";
import { useVerificationTokenCore } from "./useVerificationTokenCore";

const schema = z.object({
  token: z.string().min(1),
});

export async function verifyEmailCore(
  ctx: CoreContext,
  options: {
    token: string;
  },
): Promise<ActionResponse> {
  const { parsedRequest, prisma, config, endpoints } = ctx;
  const { logger } = config;
  const { ipAddress } = parsedRequest ?? {};

  logger?.info("verifyEmailCore called", {
    ip: ipAddress,
  });

  try {
    const parsed = schema.safeParse(options);
    if (!parsed.success) {
      logger?.warn("verifyEmailCore invalid input", {
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
      config.protection.rateLimit.endpoints.verifyEmail.enabled &&
      ipAddress
    ) {
      const limiter = endpoints.verifyEmail;
      if (!limiter) {
        logger?.error("verifyEmail rateLimiter not initialized", {
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
        logger?.warn("verifyEmail rate limit exceeded", {
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
      type: "CONFIRM_EMAIL_AFTER_REGISTER",
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

    await prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        isEmailVerified: true,
      },
    });

    logger?.info("verifyEmailCore success", { userId });

    return {
      success: true,
      status: 200,
      message: "Email verified",
      data: null,
    };
  } catch (error) {
    logger?.error("verifyEmailCore error", {
      error: error instanceof Error ? error.message : String(error),
      ip: ipAddress,
    });

    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred while verifying the email",
      code: ErrorCodes.INTERNAL_ERROR,
      data: null,
    };
  }
}
