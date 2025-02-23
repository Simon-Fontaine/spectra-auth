import { type User, VerificationType } from "@prisma/client";
import { z } from "zod";
import { hashPassword } from "../security";
import type { AegisContext, AegisResponse, PasswordConfig } from "../types";
import { fail, limitIpAddress, success } from "../utils";
import {
  getEmailSchema,
  getPasswordSchema,
  getUsernameSchema,
} from "../validations";
import { createVerificationCore } from "./createVerificationCore";

interface RegisterRequest {
  username: string;
  email: string;
  password: string;
}

const schema = (policy: PasswordConfig["rules"]) =>
  z.object({
    username: getUsernameSchema(),
    email: getEmailSchema(),
    password: getPasswordSchema("Password", policy),
  });

export async function registerUserCore(
  ctx: AegisContext,
  options: RegisterRequest,
): Promise<AegisResponse<Omit<User, "passwordHash">>> {
  const { config, prisma, req, endpoints } = ctx;
  const { logger } = config;

  logger?.debug("registerUserCore invoked", {
    username: options.username,
    email: options.email,
    ipAddress: req.ipAddress,
  });

  try {
    if (!config.registration.enabled) {
      logger?.warn("registerUserCore registration disabled", {
        ipAddress: req.ipAddress,
      });
      return fail(
        "REGISTER_NOT_ENABLED",
        "Registration is currently disabled.",
      );
    }

    const parsed = schema(config.password.rules).safeParse(options);
    if (!parsed.success) {
      logger?.debug("registerUserCore validation error", {
        issues: parsed.error.issues,
        ipAddress: req.ipAddress,
      });
      return fail("REGISTER_INVALID_REQUEST", "Invalid registration data.");
    }
    const { username, email, password } = parsed.data;

    if (config.registration.requireInvitation) {
      logger?.debug("registerUserCore - invitation required", {
        email,
        ipAddress: req.ipAddress,
      });

      const invitation = await prisma.invitation.findUnique({
        where: { email },
      });

      if (!invitation) {
        logger?.warn("registerUserCore - invitation not found", {
          email,
          ipAddress: req.ipAddress,
        });
        return fail(
          "REGISTER_INVITATION_NOT_FOUND",
          "Invitation not found. Please contact support.",
        );
      }

      if (invitation.expiresAt < new Date()) {
        logger?.warn("registerUserCore - invitation expired", {
          invitationId: invitation.id,
          email,
          ipAddress: req.ipAddress,
        });
        return fail(
          "REGISTER_INVITATION_EXPIRED",
          "Invitation has expired. Please contact support.",
        );
      }

      await prisma.invitation.delete({
        where: { email },
      });

      logger?.info("registerUserCore - invitation accepted", {
        invitationId: invitation.id,
        email,
        ipAddress: req.ipAddress,
      });
    }

    if (config.rateLimit.endpoints.register?.enabled && req.ipAddress) {
      const limiter = endpoints.register;
      if (!limiter) {
        logger?.error("registerUserCore - missing rate-limit endpoint", {
          ipAddress: req.ipAddress,
        });
        return fail(
          "REGISTER_RATE_LIMIT_ERROR",
          "Server misconfiguration. Please try again later.",
        );
      }
      const limit = await limitIpAddress(req.ipAddress, limiter);
      if (!limit.success) {
        logger?.warn("registerUserCore rate limit exceeded", {
          ipAddress: req.ipAddress,
        });
        return fail(
          "REGISTER_RATE_LIMIT_EXCEEDED",
          "Too many requests. Please try again later.",
        );
      }
    }

    const existingUsername = await prisma.user.findUnique({
      where: { username },
    });
    if (existingUsername) {
      logger?.warn("registerUserCore username exists", {
        username,
        ipAddress: req.ipAddress,
      });
      return fail("REGISTER_USERNAME_EXISTS", "Username already taken.");
    }

    const existingEmail = await prisma.user.findUnique({ where: { email } });
    if (existingEmail) {
      logger?.warn("registerUserCore email exists", {
        email,
        ipAddress: req.ipAddress,
      });
      return fail("REGISTER_EMAIL_EXISTS", "Email already in use.");
    }

    const hashedPasswordResp = await hashPassword({ password, config });
    if (!hashedPasswordResp.success) {
      logger?.error("registerUserCore failed to hash password", {
        error: hashedPasswordResp.error.message,
        ipAddress: req.ipAddress,
      });
      return fail("REGISTER_PASSWORD_HASH_ERROR", "Unable to hash password.");
    }

    const user = await prisma.user.create({
      data: {
        username,
        email,
        passwordHash: hashedPasswordResp.data,
      },
    });

    if (config.account.requireEmailVerification) {
      const verification = await createVerificationCore(ctx, {
        userId: user.id,
        type: VerificationType.COMPLETE_EMAIL_VERIFICATION,
      });

      if (!verification.success) {
        logger?.error("registerUserCore verification creation failed", {
          error: verification.error.message,
          userId: user.id,
          ipAddress: req.ipAddress,
        });
        return fail(
          "REGISTER_VERIFICATION_ERROR",
          "Failed to generate verification token.",
        );
      }

      await config.email.sendEmailVerification({
        ctx,
        to: email,
        token: verification.data.token,
      });
    }

    logger?.info("registerUserCore - user created successfully", {
      userId: user.id,
      username,
      email,
      ipAddress: req.ipAddress,
    });

    const { passwordHash, ...rest } = user;
    return success(rest);
  } catch (error) {
    logger?.error("registerUserCore unexpected failure", {
      error: error instanceof Error ? error.message : String(error),
      ipAddress: req.ipAddress,
    });
    return fail("REGISTER_ERROR", "Failed to register user. Please try again.");
  }
}
