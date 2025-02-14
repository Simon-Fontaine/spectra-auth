import { VerificationType } from "@prisma/client";
import type { Ratelimit } from "@upstash/ratelimit";
import { sendPasswordResetEmail } from "../emails";
import {
  type ActionResponse,
  type CoreContext,
  ErrorCodes,
  type PrismaUser,
} from "../types";
import { limitIpAttempts } from "../utils";
import { initiatePasswordResetSchema } from "../validations";
import { createVerification } from "./createVerification";

export async function initiatePasswordReset(
  context: CoreContext,
  input: {
    email: string;
  },
): Promise<ActionResponse> {
  const { prisma, config, limiters, parsedRequest } = context;
  const { ipAddress } = parsedRequest ?? {};

  try {
    const validatedInput = initiatePasswordResetSchema.safeParse(input);
    if (!validatedInput.success) {
      config.logger.securityEvent("INVALID_INPUT", {
        route: "initiatePasswordReset",
        ipAddress,
      });
      return {
        success: false,
        status: 400,
        message: "Invalid input provided",
        code: ErrorCodes.INVALID_INPUT,
      };
    }
    const { email } = validatedInput.data;

    if (config.rateLimiting.initiatePasswordReset.enabled && ipAddress) {
      const limiter = limiters.initiatePasswordReset as Ratelimit;
      const limit = await limitIpAttempts({ ipAddress, limiter });

      if (!limit.success) {
        config.logger.securityEvent("RATE_LIMIT_EXCEEDED", {
          route: "initiatePasswordReset",
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
      where: { email: email },
    })) as PrismaUser | null;

    // IMPORTANT:  Return success even if the user doesn't exist.  This prevents email enumeration.
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
    await sendPasswordResetEmail({
      toEmail: existingUser.email,
      token,
      config,
    });

    config.logger.securityEvent("PASSWORD_RESET_INITIATED", {
      email: input.email,
    });

    return {
      success: true,
      status: 200,
      message: "If that email exists, a reset link was sent.",
    };
  } catch (error) {
    config.logger.error("Error initiating password reset", {
      error,
      email: input.email,
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
