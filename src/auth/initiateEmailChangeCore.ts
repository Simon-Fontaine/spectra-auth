import { VerificationType } from "@prisma/client";
import { z } from "zod";
import type { AegisContext, AegisResponse } from "../types";
import { fail, limitIpAddress, success } from "../utils";
import { getEmailSchema } from "../validations";
import { createVerificationCore } from "./verifications";

interface EmailChangeRequest {
  newEmail: string;
}

const schema = z.object({
  newEmail: getEmailSchema(),
});

export async function initiateEmailChangeCore(
  ctx: AegisContext,
  options: EmailChangeRequest,
): Promise<AegisResponse<boolean>> {
  const { config, prisma, req, auth, endpoints } = ctx;
  const { logger } = config;

  logger?.debug("initiateEmailChangeCore invoked", {
    newEmail: options.newEmail,
    oldEmail: auth.user?.email,
    ipAddress: req.ipAddress,
  });

  try {
    const parsed = schema.safeParse(options);
    if (!parsed.success) {
      logger?.debug("initiateEmailChangeCore validation error", {
        issues: parsed.error.issues,
        ipAddress: req.ipAddress,
      });
      return fail("EMAIL_CHANGE_INVALID_REQUEST", "Invalid email format.");
    }
    const { newEmail } = parsed.data;

    if (
      config.rateLimit.endpoints.initiateEmailChange?.enabled &&
      req.ipAddress
    ) {
      const limiter = endpoints.initiateEmailChange;
      if (!limiter) {
        logger?.error("initiateEmailChangeCore missing rate-limit endpoint", {
          ipAddress: req.ipAddress,
        });
        return fail(
          "EMAIL_CHANGE_RATE_LIMIT_ERROR",
          "Server misconfiguration. Please try again later.",
        );
      }
      const limit = await limitIpAddress(req.ipAddress, limiter);
      if (!limit.success) {
        logger?.warn("initiateEmailChangeCore rate limit exceeded", {
          ipAddress: req.ipAddress,
        });
        return fail(
          "EMAIL_CHANGE_RATE_LIMIT_EXCEEDED",
          "Too many requests. Please try again later.",
        );
      }
    }

    if (!auth.isAuthenticated || !auth.user) {
      logger?.warn("initiateEmailChangeCore user not authenticated", {
        ipAddress: req.ipAddress,
      });
      return fail(
        "EMAIL_CHANGE_NOT_AUTHENTICATED",
        "You must be logged in to change your email.",
      );
    }

    if (auth.user.email.toLowerCase() === newEmail.toLowerCase()) {
      logger?.warn("initiateEmailChangeCore email is the same", {
        ipAddress: req.ipAddress,
      });
      return fail(
        "EMAIL_CHANGE_SAME_EMAIL",
        "The new email matches your current email.",
      );
    }

    const existingUser = await prisma.user.findFirst({
      where: { email: newEmail },
    });
    if (existingUser) {
      logger?.warn("initiateEmailChangeCore email already in use", {
        newEmail,
        ipAddress: req.ipAddress,
      });
      return fail(
        "EMAIL_CHANGE_EMAIL_IN_USE",
        "This email is already in use by another user.",
      );
    }

    const verificationResp = await createVerificationCore(ctx, {
      userId: auth.user.id,
      type: VerificationType.COMPLETE_EMAIL_CHANGE,
    });
    if (!verificationResp.success) {
      logger?.error("initiateEmailChangeCore verification creation failed", {
        ipAddress: req.ipAddress,
        error: verificationResp.error.message,
      });
      return fail(
        "EMAIL_CHANGE_VERIFICATION_CREATION_ERROR",
        "Failed to create verification token.",
      );
    }

    await config.email.sendEmailChange({
      ctx,
      to: newEmail,
      token: verificationResp.data.token,
    });

    await prisma.user.update({
      where: { id: auth.user.id },
      data: { pendingEmail: newEmail },
    });

    logger?.info("initiateEmailChangeCore email change initiated", {
      userId: auth.user.id,
      oldEmail: auth.user.email,
      newEmail,
      ipAddress: req.ipAddress,
    });

    return success(true);
  } catch (error) {
    logger?.error("initiateEmailChangeCore unexpected failure", {
      error: error instanceof Error ? error.message : String(error),
      ipAddress: req.ipAddress,
    });
    return fail(
      "EMAIL_CHANGE_INITIATION_ERROR",
      "Failed to initiate email change. Please try again.",
    );
  }
}
