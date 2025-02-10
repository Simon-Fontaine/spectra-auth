import { type PrismaClient, VerificationType } from "@prisma/client";
import type { Ratelimit } from "@upstash/ratelimit";
import type { AegisAuthConfig } from "../config";
import { type ActionResponse, ErrorCodes, type Limiters } from "../types";
import { type ParsedRequestData, limitIpAttempts } from "../utils";
import { useVerificationToken } from "./useVerificationToken";

export async function verifyEmail(
  context: {
    prisma: PrismaClient;
    config: Required<AegisAuthConfig>;
    limiters: Limiters;
    parsedRequest: ParsedRequestData;
  },
  input: {
    token: string;
  },
): Promise<ActionResponse> {
  const { prisma, config, limiters, parsedRequest } = context;
  const { ipAddress } = parsedRequest;

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
    token: input.token,
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
}
