import { type PrismaClient, VerificationType } from "@prisma/client";
import type { Ratelimit } from "@upstash/ratelimit";
import type { AegisAuthConfig } from "../config";
import { hashPassword } from "../security";
import { type ActionResponse, ErrorCodes, type Limiters } from "../types";
import { type ParsedRequestData, limitIpAttempts } from "../utils";
import { completePasswordResetSchema } from "../validations";
import { useVerificationToken } from "./useVerificationToken";

export async function completePasswordReset(
  context: {
    prisma: PrismaClient;
    config: Required<AegisAuthConfig>;
    limiters: Limiters;
    parsedRequest: ParsedRequestData;
  },
  input: {
    token: string;
    newPassword: string;
  },
): Promise<ActionResponse> {
  const { prisma, config, limiters, parsedRequest } = context;
  const { ipAddress } = parsedRequest;

  try {
    // Validate input
    const validatedInput = completePasswordResetSchema.safeParse(input);
    if (!validatedInput.success) {
      config.logger.securityEvent("INVALID_INPUT", {
        route: "completePasswordReset",
        ipAddress,
      });
      return {
        success: false,
        status: 400,
        message: "Invalid input provided",
        code: ErrorCodes.INVALID_INPUT,
      };
    }
    const { token, newPassword } = validatedInput.data;

    if (config.rateLimiting.passwordReset.enabled && ipAddress) {
      const limiter = limiters.passwordReset as Ratelimit;
      const limit = await limitIpAttempts({ ipAddress, limiter });

      if (!limit.success) {
        config.logger.securityEvent("RATE_LIMIT_EXCEEDED", {
          route: "passwordReset",
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
      type: VerificationType.PASSWORD_RESET,
    });

    if (!verification.success || !verification.data?.verification) {
      config.logger.securityEvent("INVALID_TOKEN", {
        route: "passwordReset",
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
    const hashedPassword = await hashPassword({
      password: newPassword,
      config,
    });

    await prisma.$transaction([
      prisma.user.update({
        where: { id: userId },
        data: { password: hashedPassword },
      }),
      prisma.session.updateMany({
        where: {
          userId: userId,
          isRevoked: false,
        },
        data: { isRevoked: true },
      }),
    ]);

    config.logger.securityEvent("PASSWORD_RESET", {
      ipAddress,
      userId: userId,
    });

    return {
      success: true,
      status: 200,
      message: "Password reset successfully.",
    };
  } catch (error) {
    config.logger.error("Error completing password reset", {
      error,
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
