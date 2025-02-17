import { z } from "zod";
import {
  type ActionResponse,
  type CoreContext,
  ErrorCodes,
  type PrismaUser,
} from "../types";
import { limitIpAddress } from "../utils";
import { getEmailSchema } from "../validations";
import { createVerificationCore } from "./createVerificationCore";

const schema = z.object({
  email: getEmailSchema(),
});

export async function initiatePasswordResetCore(
  ctx: CoreContext,
  options: {
    email: string;
  },
): Promise<ActionResponse> {
  const { parsedRequest, prisma, config, endpoints } = ctx;
  const { logger } = config;
  const { ipAddress } = parsedRequest ?? {};

  logger?.info("initiatePasswordResetCore called", { email: options.email });

  try {
    const parsed = schema.safeParse(options);
    if (!parsed.success) {
      logger?.warn("initiatePasswordResetCore invalid input", {
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

    const { email } = parsed.data;

    if (
      config.protection.rateLimit.endpoints.initiatePasswordReset.enabled &&
      ipAddress
    ) {
      const limiter = endpoints.initiatePasswordReset;
      if (!limiter) {
        logger?.error("initiatePasswordReset rateLimiter not initialized", {
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
        logger?.warn("initiatePasswordReset rate limit exceeded", {
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

    const user = (await prisma.user.findUnique({
      where: { email },
    })) as PrismaUser | null;

    if (!user) {
      logger?.warn("initiatePasswordResetCore user not found", {
        email,
        ip: ipAddress,
      });

      return {
        success: true,
        status: 200,
        message: "If that email exists, a reset link was sent.",
      };
    }

    const verificationRequest = await createVerificationCore(ctx, {
      userId: user.id,
      type: "INITIATE_PASSWORD_RESET",
    });

    if (
      !verificationRequest.success ||
      !verificationRequest.data?.verification
    ) {
      return verificationRequest;
    }

    const { token } = verificationRequest.data.verification;
    // TODO: Send email with token
    console.log("Password reset token:", token);

    logger?.info("initiatePasswordResetCore success", {
      email,
      ip: ipAddress,
    });

    return {
      success: true,
      status: 200,
      message: "If that email exists, a reset link was sent.",
    };
  } catch (error) {
    logger?.error("initiatePasswordResetCore error", {
      error: error instanceof Error ? error.message : String(error),
      email: options.email,
      ip: ipAddress,
    });

    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred while initiating password reset",
      code: ErrorCodes.INTERNAL_ERROR,
      data: null,
    };
  }
}
