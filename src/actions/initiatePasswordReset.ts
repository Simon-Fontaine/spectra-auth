import { type PrismaClient, VerificationType } from "@prisma/client";
import type { AegisAuthConfig } from "../config";
import { sendPasswordResetEmail } from "../emails";
import { type ActionResponse, ErrorCodes, type PrismaUser } from "../types";
import { createRouteLimiter, limitIpAttempts } from "../utils";
import { createVerification } from "./createVerification";

export async function initiatePasswordReset({
  options,
  prisma,
  config,
}: {
  options: {
    input: {
      email: string;
    };
    ipAddress?: string;
  };
  prisma: PrismaClient;
  config: Required<AegisAuthConfig>;
}): Promise<ActionResponse> {
  const { input, ipAddress } = options;

  if (config.rateLimiting.forgotPassword.enabled && ipAddress) {
    const limiter = createRouteLimiter({ routeKey: "forgotPassword", config });
    const limit = await limitIpAttempts({ ipAddress, rateLimiter: limiter });

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

  const verification = await createVerification({
    options: {
      userId: existingUser.id,
      type: VerificationType.PASSWORD_RESET,
    },
    prisma,
    config,
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
