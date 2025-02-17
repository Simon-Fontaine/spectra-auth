import { z } from "zod";
import {
  type ActionResponse,
  type CoreContext,
  ErrorCodes,
  type PrismaVerification,
} from "../types";

const schema = z.object({
  token: z.string().min(1),
  type: z.string().min(1),
});

export async function useVerificationTokenCore(
  ctx: CoreContext,
  options: {
    token: string;
    type: string;
  },
): Promise<ActionResponse<{ verification?: PrismaVerification }>> {
  const { prisma, config } = ctx;
  const { logger } = config;

  logger?.info("useVerificationToken called", { token: options?.token });

  try {
    const parsed = schema.safeParse(options);
    if (!parsed.success) {
      logger?.warn("useVerificationToken invalid input", {
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

    const now = new Date();
    const { token, type } = parsed.data;

    const verification = (await prisma.verification.findFirst({
      where: {
        token,
      },
    })) as PrismaVerification;

    if (!verification) {
      logger?.warn("useVerificationToken token not found", {
        token: options?.token,
      });

      return {
        success: false,
        status: 404,
        message: "Verification token not found",
        code: ErrorCodes.VERIFICATION_NOT_FOUND,
        data: null,
      };
    }

    if (verification.type !== type) {
      logger?.warn("useVerificationToken token type mismatch", {
        token: options?.token,
      });

      return {
        success: false,
        status: 400,
        message: "Verification token type mismatch",
        code: ErrorCodes.VERIFICATION_INVALID,
        data: null,
      };
    }

    if (verification.expiresAt < now) {
      logger?.warn("useVerificationToken token expired", {
        token: options?.token,
      });

      return {
        success: false,
        status: 400,
        message: "Verification token expired",
        code: ErrorCodes.VERIFICATION_EXPIRED,
        data: null,
      };
    }

    if (verification.usedAt) {
      logger?.warn("useVerificationToken token already used", {
        token: options?.token,
      });

      return {
        success: false,
        status: 400,
        message: "Verification token already used",
        code: ErrorCodes.VERIFICATION_USED,
        data: null,
      };
    }

    await prisma.verification.update({
      where: {
        id: verification.id,
      },
      data: {
        usedAt: now,
      },
    });

    logger?.info("useVerificationToken success", { token: options?.token });

    return {
      success: true,
      status: 200,
      message: "Verification token valid",
      data: { verification },
    };
  } catch (error) {
    logger?.error("useVerificationToken error", {
      error: error instanceof Error ? error.message : String(error),
      token: options?.token,
    });

    return {
      success: false,
      status: 500,
      message: "An error occurred while verifying the token",
      code: ErrorCodes.INTERNAL_ERROR,
      data: null,
    };
  }
}
