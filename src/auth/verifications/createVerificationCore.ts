import { type Verification, VerificationType } from "@prisma/client";
import { z } from "zod";
import { createVerificationToken } from "../../security";
import type { AegisContext, AegisResponse } from "../../types";
import { createTime, fail, success } from "../../utils";

interface VerificationRequest {
  userId: string;
  type: VerificationType;
  tokenExpirySeconds?: number;
}

const schema = z.object({
  userId: z.string().uuid(),
  type: z.nativeEnum(VerificationType),
  tokenExpirySeconds: z.number().int().positive().optional(),
});

export async function createVerificationCore(
  ctx: AegisContext,
  options: VerificationRequest,
): Promise<AegisResponse<Verification>> {
  const { config, prisma, req } = ctx;
  const { logger } = config;

  logger?.debug("createVerificationCore invoked", {
    userId: options.userId,
    type: options.type,
    ipAddress: req.ipAddress,
  });

  try {
    const parsed = schema.safeParse(options);
    if (!parsed.success) {
      logger?.warn("createVerificationCore - invalid request options", {
        issues: parsed.error.issues,
        ipAddress: req.ipAddress,
      });
      return fail("VERIFICATION_INVALID_OPTIONS", parsed.error.message);
    }
    const { userId, type, tokenExpirySeconds } = parsed.data;

    const user = await prisma.user.findUnique({
      where: { id: userId },
    });
    if (!user) {
      logger?.warn("createVerificationCore - user not found", {
        userId,
        ipAddress: req.ipAddress,
      });
      return fail("VERIFICATION_USER_NOT_FOUND", "User not found.");
    }

    const tokenResp = await createVerificationToken({ config });
    if (!tokenResp.success) {
      logger?.error("createVerificationCore - token generation failed", {
        ipAddress: req.ipAddress,
        error: tokenResp.error.message,
      });
      return fail("VERIFICATION_TOKEN_CREATION_ERROR", tokenResp.error.message);
    }

    const effectiveExpirySeconds =
      tokenExpirySeconds || config.verification.tokenExpirySeconds;
    const expiryDate = createTime(effectiveExpirySeconds, "s").getDate();

    const verification = await prisma.verification.create({
      data: {
        type,
        userId,
        token: tokenResp.data,
        expiresAt: expiryDate,
      },
    });

    logger?.info("createVerificationCore - verification created", {
      verificationId: verification.id,
      userId,
      type,
      ipAddress: req.ipAddress,
    });

    return success(verification);
  } catch (error) {
    logger?.error("createVerificationCore - unexpected failure", {
      error: error instanceof Error ? error.message : String(error),
      ipAddress: req.ipAddress,
    });
    return fail(
      "VERIFICATION_CREATION_ERROR",
      "Failed to create verification.",
    );
  }
}
