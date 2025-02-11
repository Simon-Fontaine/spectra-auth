import { type PrismaClient, VerificationType } from "@prisma/client";
import type { Ratelimit } from "@upstash/ratelimit";
import type { AegisAuthConfig } from "../config";
import { sendVerificationEmail } from "../emails";
import {
  type ActionResponse,
  ErrorCodes,
  type Limiters,
  type PrismaUser,
} from "../types";
import { type ParsedRequestData, limitIpAttempts } from "../utils";
import { initiateEmailChangeSchema } from "../validations";
import { createVerification } from "./createVerification";

export async function initiateEmailChange(
  context: {
    prisma: PrismaClient;
    config: Required<AegisAuthConfig>;
    limiters: Limiters;
    parsedRequest: ParsedRequestData;
  },
  input: {
    userId: string;
    newEmail: string;
  },
): Promise<ActionResponse> {
  const { prisma, config, limiters, parsedRequest } = context;
  const { ipAddress } = parsedRequest ?? {};

  try {
    const validatedInput = initiateEmailChangeSchema.safeParse(input);
    if (!validatedInput.success) {
      config.logger.securityEvent("INVALID_INPUT", {
        route: "initiateEmailChange",
        ipAddress,
      });
      return {
        success: false,
        status: 400,
        message: "Invalid input provided",
        code: ErrorCodes.INVALID_INPUT,
      };
    }
    const { userId, newEmail } = validatedInput.data;

    if (config.rateLimiting.initiateEmailChange.enabled && ipAddress) {
      const limiter = limiters.initiateEmailChange as Ratelimit;
      const limit = await limitIpAttempts({ ipAddress, limiter });

      if (!limit.success) {
        config.logger.securityEvent("RATE_LIMIT_EXCEEDED", {
          route: "initiateEmailChange",
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

    const existingUser = (await prisma.user.findFirst({
      where: {
        OR: [{ email: newEmail }, { pendingEmail: newEmail }],
      },
    })) as PrismaUser | null;

    if (existingUser) {
      return {
        success: false,
        status: 400,
        message: "Email is already in use",
        code: ErrorCodes.EMAIL_IN_USE,
      };
    }

    await prisma.user.update({
      where: { id: userId },
      data: { pendingEmail: newEmail },
    });

    const verification = await createVerification(context, {
      userId,
      type: VerificationType.EMAIL_CHANGE,
    });

    if (!verification.success || !verification.data?.verification) {
      return {
        success: false,
        status: 500,
        message: "Failed to create email change verification.",
        code: ErrorCodes.INTERNAL_SERVER_ERROR,
      };
    }

    const { token } = verification.data.verification;
    await sendVerificationEmail({
      toEmail: newEmail,
      token,
      config: context.config,
    });

    return {
      success: true,
      status: 200,
      message: "Verification email sent to your new email address.",
    };
  } catch (error) {
    config.logger.error("Error initiating email change", {
      error,
      email: input.newEmail,
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
