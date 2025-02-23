import { type Verification, VerificationType } from "@prisma/client";
import { z } from "zod";
import type { AegisContext, AegisResponse } from "../types";
import { fail, success } from "../utils";

interface VerificationTokenRequest {
  token: string;
  type: VerificationType;
}

const schema = z.object({
  token: z.string().min(1),
  type: z.nativeEnum(VerificationType),
});

export async function useVerificationTokenCore(
  ctx: AegisContext,
  options: VerificationTokenRequest,
): Promise<AegisResponse<Verification>> {
  const { config, prisma, req } = ctx;
  const { logger } = config;

  logger?.debug("useVerificationTokenCore invoked", {
    token: options.token,
    type: options.type,
    ipAddress: req.ipAddress,
  });

  try {
    const parsed = schema.safeParse(options);
    if (!parsed.success) {
      logger?.warn("useVerificationTokenCore - invalid request options", {
        issues: parsed.error.issues,
        ipAddress: req.ipAddress,
      });
      return fail("VERIFICATION_INVALID_OPTIONS", parsed.error.message);
    }

    const { token, type } = parsed.data;
    const now = new Date();

    const verification = await prisma.verification.findUnique({
      where: { token },
    });
    if (!verification) {
      logger?.warn("useVerificationTokenCore - verification not found", {
        token,
        ipAddress: req.ipAddress,
      });
      return fail("VERIFICATION_NOT_FOUND", "Verification record not found.");
    }

    if (verification.type !== type) {
      logger?.warn("useVerificationTokenCore - type mismatch", {
        verificationId: verification.id,
        expectedType: type,
        actualType: verification.type,
        ipAddress: req.ipAddress,
      });
      return fail("VERIFICATION_TYPE_MISMATCH", "Verification type mismatch.");
    }

    if (verification.expiresAt < now) {
      logger?.warn("useVerificationTokenCore - verification expired", {
        verificationId: verification.id,
        ipAddress: req.ipAddress,
      });
      return fail("VERIFICATION_EXPIRED", "Verification is expired.");
    }

    if (verification.usedAt) {
      logger?.warn("useVerificationTokenCore - already used", {
        verificationId: verification.id,
        usedAt: verification.usedAt.toISOString(),
        ipAddress: req.ipAddress,
      });
      return fail(
        "VERIFICATION_ALREADY_USED",
        "Verification has already been used.",
      );
    }

    const updatedVerification = await prisma.verification.update({
      where: { id: verification.id },
      data: { usedAt: now },
    });

    logger?.info("useVerificationTokenCore - verification consumed", {
      verificationId: verification.id,
      userId: verification.userId,
      ipAddress: req.ipAddress,
    });

    return success(updatedVerification);
  } catch (error) {
    logger?.error("useVerificationTokenCore - unexpected failure", {
      error: error instanceof Error ? error.message : String(error),
      ipAddress: req.ipAddress,
    });
    return fail("VERIFICATION_USE_ERROR", "Failed to use verification token.");
  }
}
