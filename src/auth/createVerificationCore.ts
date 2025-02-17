import { z } from "zod";
import { createVerificationToken } from "../security";
import {
  type ActionResponse,
  type CoreContext,
  ErrorCodes,
  type PrismaVerification,
} from "../types";
import { createTime } from "../utils";

const schema = z.object({
  userId: z.string().uuid("Invalid user ID provided."),
  type: z.string().min(1),
  tokenExpirySeconds: z.number().int().positive().optional(),
});

export async function createVerificationCore(
  ctx: CoreContext,
  options: {
    userId: string;
    type: string;
    tokenExpirySeconds?: number;
  },
): Promise<ActionResponse<{ verification?: PrismaVerification }>> {
  const { prisma, config } = ctx;
  const { logger } = config;

  logger?.info("createVerification called", { userId: options?.userId });

  try {
    const parsed = schema.safeParse(options);
    if (!parsed.success) {
      logger?.warn("createVerification invalid input", {
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

    const { userId, type, tokenExpirySeconds } = parsed.data;
    const token = await createVerificationToken({ config });
    const expiresAt = createTime(
      tokenExpirySeconds || config.security.verification.tokenExpirySeconds,
      "s",
    );

    const verification = (await prisma.verification.create({
      data: {
        token,
        userId,
        type,
        expiresAt: expiresAt.getDate(),
      },
    })) as PrismaVerification;

    logger?.info("createVerification success", { userId: options?.userId });

    return {
      success: true,
      status: 201,
      message: "Verification created",
      data: { verification },
    };
  } catch (error) {
    logger?.error("createVerification error", {
      error: error instanceof Error ? error.message : String(error),
      userId: options?.userId,
    });

    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred while creating the verification",
      code: ErrorCodes.INTERNAL_ERROR,
      data: null,
    };
  }
}
