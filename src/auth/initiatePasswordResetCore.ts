import { VerificationType } from "@prisma/client";
import { z } from "zod";
import type { AegisContext, AegisResponse } from "../types";
import { fail, limitIpAddress, success } from "../utils";
import { getEmailSchema } from "../validations";
import { createVerificationCore } from "./verifications";

interface PasswordResetRequest {
  email: string;
}

const schema = z.object({
  email: getEmailSchema(),
});

export async function initiatePasswordResetCore(
  ctx: AegisContext,
  options: PasswordResetRequest,
): Promise<AegisResponse<boolean>> {
  const { config, prisma, req, endpoints } = ctx;
  const { logger } = config;

  logger?.debug("initiatePasswordResetCore invoked", {
    email: options.email,
    ipAddress: req.ipAddress,
  });

  try {
    const parsed = schema.safeParse(options);
    if (!parsed.success) {
      logger?.debug("initiatePasswordResetCore validation error", {
        issues: parsed.error.issues,
        ipAddress: req.ipAddress,
      });
      return fail("PASSWORD_RESET_INVALID_REQUEST", "Invalid email.");
    }
    const { email } = parsed.data;

    if (
      config.rateLimit.endpoints.initiatePasswordReset?.enabled &&
      req.ipAddress
    ) {
      const limiter = endpoints.initiatePasswordReset;
      if (!limiter) {
        logger?.error("initiatePasswordResetCore missing rate-limit endpoint", {
          ipAddress: req.ipAddress,
        });
        return fail(
          "PASSWORD_RESET_RATE_LIMIT_ERROR",
          "Server misconfiguration. Please try again later.",
        );
      }
      const limit = await limitIpAddress(req.ipAddress, limiter);
      if (!limit.success) {
        logger?.warn("initiatePasswordResetCore rate limit exceeded", {
          ipAddress: req.ipAddress,
        });
        return fail(
          "PASSWORD_RESET_RATE_LIMIT_EXCEEDED",
          "Too many requests. Please try again later.",
        );
      }
    }

    const existingUser = await prisma.user.findFirst({ where: { email } });
    if (!existingUser) {
      logger?.warn(
        "initiatePasswordResetCore user not found (but not disclosed)",
        {
          email,
          ipAddress: req.ipAddress,
        },
      );
      return success(true);
    }

    const verificationResp = await createVerificationCore(ctx, {
      userId: existingUser.id,
      type: VerificationType.COMPLETE_PASSWORD_RESET,
    });
    if (!verificationResp.success) {
      logger?.error("initiatePasswordResetCore verification creation failed", {
        ipAddress: req.ipAddress,
        error: verificationResp.error.message,
      });
      return fail(
        "PASSWORD_RESET_VERIFICATION_CREATION_ERROR",
        "Failed to create verification token.",
      );
    }

    await config.email.sendPasswordReset({
      ctx,
      to: email,
      token: verificationResp.data.token,
    });

    logger?.info("initiatePasswordResetCore password reset email sent", {
      userId: existingUser.id,
      email,
      ipAddress: req.ipAddress,
    });

    return success(true);
  } catch (error) {
    logger?.error("initiatePasswordResetCore unexpected failure", {
      error: error instanceof Error ? error.message : String(error),
      ipAddress: req.ipAddress,
    });
    return fail(
      "PASSWORD_RESET_INITIATION_ERROR",
      "Failed to initiate password reset. Please try again.",
    );
  }
}
