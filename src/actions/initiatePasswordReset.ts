import { type PrismaClient, VerificationType } from "@prisma/client";
import type { Ratelimit } from "@upstash/ratelimit";
import type { AegisAuthConfig } from "../config";
import { sendPasswordResetEmail } from "../emails";
import {
  type ActionResponse,
  ErrorCodes,
  type Limiters,
  type PrismaUser,
} from "../types";
import { type ParsedRequestData, limitIpAttempts } from "../utils";
import { createVerification } from "./createVerification";

export async function initiatePasswordReset(
  context: {
    prisma: PrismaClient;
    config: Required<AegisAuthConfig>;
    limiters: Limiters;
    parsedRequest: ParsedRequestData;
  },
  input: {
    email: string;
  },
): Promise<ActionResponse> {
  const { prisma, config, limiters, parsedRequest } = context;
  const { ipAddress } = parsedRequest;

  if (config.rateLimiting.forgotPassword.enabled && ipAddress) {
    const limiter = limiters.forgotPassword as Ratelimit;
    const limit = await limitIpAttempts({ ipAddress, limiter });

    if (!limit.success) {
      config.logger.securityEvent("RATE_LIMIT_EXCEEDED", {
        route: "forgotPassword",
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

  const existingUser = (await prisma.user.findUnique({
    where: { email: input.email },
  })) as PrismaUser | null;

  if (!existingUser) {
    config.logger.securityEvent("PASSWORD_RESET_INITIATED_FAILED", {
      email: input.email,
    });
    return {
      success: true,
      status: 200,
      message: "If that email exists, a reset link was sent.",
    };
  }

  const verification = await createVerification(context, {
    userId: existingUser.id,
    type: VerificationType.PASSWORD_RESET,
  });

  if (!verification.success || !verification.data?.verification) {
    config.logger.securityEvent("PASSWORD_RESET_INITIATED_FAILED", {
      email: input.email,
    });
    return {
      success: false,
      status: 500,
      message: "Failed to create verification",
      code: ErrorCodes.INTERNAL_SERVER_ERROR,
    };
  }

  const { token } = verification.data.verification;
  await sendPasswordResetEmail({ toEmail: existingUser.email, token, config });

  config.logger.securityEvent("PASSWORD_RESET_INITIATED", {
    email: input.email,
  });

  return {
    success: true,
    status: 200,
    message: "If that email exists, a reset link was sent.",
  };
}
