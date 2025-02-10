import { type PrismaClient, VerificationType } from "@prisma/client";
import type { Ratelimit } from "@upstash/ratelimit";
import type { AegisAuthConfig } from "../config";
import { hashPassword } from "../security";
import { type ActionResponse, ErrorCodes, type Limiters } from "../types";
import { limitIpAttempts } from "../utils";
import { useVerificationToken } from "./useVerificationToken";

export async function completePasswordReset({
  options,
  prisma,
  config,
  limiters,
}: {
  options: {
    input: {
      token: string;
      newPassword: string;
    };
    ipAddress?: string;
  };
  prisma: PrismaClient;
  config: Required<AegisAuthConfig>;
  limiters: Limiters;
}): Promise<ActionResponse> {
  const { input, ipAddress } = options;

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

  const verification = await useVerificationToken({
    options: {
      input: {
        token: input.token,
        type: VerificationType.PASSWORD_RESET,
      },
    },
    prisma,
    config,
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
    password: input.newPassword,
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
}
