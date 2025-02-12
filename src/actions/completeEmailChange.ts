import { type PrismaClient, VerificationType } from "@prisma/client";
import type { Ratelimit } from "@upstash/ratelimit";
import type { AegisAuthConfig } from "../config";
import {
  type ActionResponse,
  ErrorCodes,
  type Limiters,
  type PrismaUser,
} from "../types";
import { type ParsedRequestData, limitIpAttempts } from "../utils";
import { completeEmailChangeSchema } from "../validations";
import { useVerificationToken } from "./useVerificationToken";

export async function completeEmailChange(
  context: {
    prisma: PrismaClient;
    config: AegisAuthConfig;
    limiters: Limiters;
    parsedRequest: ParsedRequestData;
  },
  input: {
    token: string;
  },
): Promise<ActionResponse> {
  const { prisma, config, limiters, parsedRequest } = context;
  const { ipAddress } = parsedRequest ?? {};

  try {
    const validatedInput = completeEmailChangeSchema.safeParse(input);
    if (!validatedInput.success) {
      config.logger.securityEvent("INVALID_INPUT", {
        route: "completeEmailChange",
        ipAddress,
      });
      return {
        success: false,
        status: 400,
        message: "Invalid input provided",
        code: ErrorCodes.INVALID_INPUT,
      };
    }
    const { token } = validatedInput.data;

    if (config.rateLimiting.completeEmailChange.enabled && ipAddress) {
      const limiter = limiters.completeEmailChange as Ratelimit;
      const limit = await limitIpAttempts({ ipAddress, limiter });

      if (!limit.success) {
        config.logger.securityEvent("RATE_LIMIT_EXCEEDED", {
          route: "completeEmailChange",
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
      type: VerificationType.EMAIL_CHANGE,
    });

    if (!verification.success || !verification.data?.verification) {
      config.logger.securityEvent("INVALID_TOKEN", {
        route: "completeEmailChange",
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
    const user = (await prisma.user.findUnique({
      where: { id: userId },
    })) as PrismaUser | null;
    if (!user || !user.pendingEmail) {
      return {
        success: false,
        status: 400,
        message: "No pending email change found.",
        code: ErrorCodes.INVALID_INPUT,
      };
    }

    await prisma.user.update({
      where: { id: userId },
      data: {
        email: user.pendingEmail,
        pendingEmail: null,
      },
    });

    return {
      success: true,
      status: 200,
      message: "Email change completed successfully.",
    };
  } catch (error) {
    config.logger.error("Error completing email change", {
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
