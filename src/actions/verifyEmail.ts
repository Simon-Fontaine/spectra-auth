import { VerificationType } from "@prisma/client";
import type { Ratelimit } from "@upstash/ratelimit";
import { type ActionResponse, type CoreContext, ErrorCodes } from "../types";
import { limitIpAttempts } from "../utils";
import { verifyEmailSchema } from "../validations";
import { useVerificationToken } from "./useVerificationToken";

export async function verifyEmail(
  context: CoreContext,
  input: {
    token: string;
  },
): Promise<ActionResponse> {
  const { prisma, config, limiters, parsedRequest } = context;
  const { ipAddress } = parsedRequest ?? {};

  try {
    const validatedInput = verifyEmailSchema.safeParse(input);
    if (!validatedInput.success) {
      config.logger.securityEvent("INVALID_INPUT", { route: "verifyEmail" });
      return {
        success: false,
        status: 400,
        message: "Invalid input provided",
        code: ErrorCodes.INVALID_INPUT,
      };
    }
    const { token } = validatedInput.data;

    if (config.rateLimiting.verifyEmail.enabled && ipAddress) {
      const limiter = limiters.verifyEmail as Ratelimit;
      const limit = await limitIpAttempts({ ipAddress, limiter });

      if (!limit.success) {
        config.logger.securityEvent("RATE_LIMIT_EXCEEDED", {
          route: "verifyEmail",
          ipAddress,
        });

        return {
          success: false,
          status: 429,
          message: "Too many attempts. Try again later.",
          code: ErrorCodes.RATE_LIMIT_EXCEEDED,
        };
      }
    }

    const verification = await useVerificationToken(context, {
      token: token,
      type: VerificationType.EMAIL_VERIFICATION,
    });

    if (!verification.success || !verification.data?.verification) {
      config.logger.securityEvent("INVALID_TOKEN", {
        route: "verifyEmail",
        ipAddress,
      });
      return {
        success: false,
        status: 400,
        message: "Invalid token.",
        code: ErrorCodes.INVALID_TOKEN,
      };
    }

    const {
      verification: { userId },
    } = verification.data;

    await prisma.user.update({
      where: { id: userId },
      data: { isEmailVerified: true },
    });

    config.logger.securityEvent("EMAIL_VERIFIED", {
      userId,
      ipAddress,
    });

    return {
      success: true,
      status: 200,
      message: "Email verified.",
    };
  } catch (error) {
    config.logger.error("Error verifying email", {
      error,
      token: input.token,
      ipAddress: parsedRequest?.ipAddress,
    });
    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred.",
      code: ErrorCodes.INTERNAL_SERVER_ERROR,
    };
  }
}
