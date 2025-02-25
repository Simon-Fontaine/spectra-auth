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
import { createVerificationCore } from "./verifications";

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
  const requestId = Math.random().toString(36).substring(2, 15);

  logger?.debug("registerUserCore - invoked", {
    requestId,
    username: options.username,
    email: options.email,
    ipAddress: req.ipAddress,
  });

  try {
    // Check if registration is enabled
    if (!config.registration.enabled) {
      logger?.warn("registerUserCore - registration disabled", {
        requestId,
        ipAddress: req.ipAddress,
      });
      return fail(
        "REGISTER_NOT_ENABLED",
        "Registration is currently disabled.",
      );
    }

    // Validate input data
    const parsed = schema(config.password.rules).safeParse(options);
    if (!parsed.success) {
      logger?.debug("registerUserCore - validation error", {
        requestId,
        issues: parsed.error.issues,
        ipAddress: req.ipAddress,
      });
      return fail("REGISTER_INVALID_REQUEST", "Invalid registration data.");
    }
    const { username, email, password } = parsed.data;

    // Normalize email and username for comparison
    const normalizedEmail = email.toLowerCase().trim();
    const normalizedUsername = username.toLowerCase().trim();

    // Handle invitation requirement
    if (config.registration.requireInvitation) {
      logger?.debug("registerUserCore - invitation required", {
        requestId,
        email: normalizedEmail,
        ipAddress: req.ipAddress,
      });

      const invitation = await prisma.invitation.findUnique({
        where: { email: normalizedEmail },
      });

      if (!invitation) {
        logger?.warn("registerUserCore - invitation not found", {
          requestId,
          email: normalizedEmail,
          ipAddress: req.ipAddress,
        });
        return fail(
          "REGISTER_INVITATION_NOT_FOUND",
          "Invitation not found. Please contact support.",
        );
      }

      if (invitation.expiresAt < new Date()) {
        logger?.warn("registerUserCore - invitation expired", {
          requestId,
          invitationId: invitation.id,
          email: normalizedEmail,
          ipAddress: req.ipAddress,
        });
        return fail(
          "REGISTER_INVITATION_EXPIRED",
          "Invitation has expired. Please contact support.",
        );
      }

      // We'll delete the invitation after successful registration
    }

    // Apply rate limiting
    if (config.rateLimit.endpoints.register?.enabled && req.ipAddress) {
      const limiter = endpoints.register;
      if (!limiter) {
        logger?.error("registerUserCore - missing rate-limit endpoint", {
          requestId,
          ipAddress: req.ipAddress,
        });
        return fail(
          "REGISTER_RATE_LIMIT_ERROR",
          "Server misconfiguration. Please try again later.",
        );
      }
      const limit = await limitIpAddress(req.ipAddress, limiter);
      if (!limit.success) {
        logger?.warn("registerUserCore - rate limit exceeded", {
          requestId,
          ipAddress: req.ipAddress,
        });
        return fail(
          "REGISTER_RATE_LIMIT_EXCEEDED",
          "Too many requests. Please try again later.",
        );
      }
    }

    // Check for existing users (use transaction to avoid race conditions)
    // This prevents registration during the small window between checking
    // for existing users and actually creating the new user
    const existingUsers = await prisma.$transaction([
      prisma.user.findUnique({ where: { username: normalizedUsername } }),
      prisma.user.findUnique({ where: { email: normalizedEmail } }),
    ]);

    const [existingUsername, existingEmail] = existingUsers;

    if (existingUsername) {
      logger?.warn("registerUserCore - username exists", {
        requestId,
        username: normalizedUsername,
        ipAddress: req.ipAddress,
      });
      return fail("REGISTER_USERNAME_EXISTS", "Username already taken.");
    }

    if (existingEmail) {
      logger?.warn("registerUserCore - email exists", {
        requestId,
        email: normalizedEmail,
        ipAddress: req.ipAddress,
      });
      return fail("REGISTER_EMAIL_EXISTS", "Email already in use.");
    }

    // Hash password
    const hashedPasswordResp = await hashPassword({ password, config });
    if (!hashedPasswordResp.success) {
      logger?.error("registerUserCore - failed to hash password", {
        requestId,
        error: hashedPasswordResp.error.message,
        ipAddress: req.ipAddress,
      });
      return fail("REGISTER_PASSWORD_HASH_ERROR", "Unable to hash password.");
    }

    // Create user with transaction for atomicity
    const user = await prisma.$transaction(async (tx) => {
      // Create the new user
      const newUser = await tx.user.create({
        data: {
          username: normalizedUsername,
          email: normalizedEmail,
          passwordHash: hashedPasswordResp.data,
          // If email verification is required, set to false, otherwise true
          isEmailVerified: !config.account.requireEmailVerification,
        },
      });

      // If using invitations, delete the used invitation
      if (config.registration.requireInvitation) {
        await tx.invitation.delete({
          where: { email: normalizedEmail },
        });
      }

      return newUser;
    });

    // Create verification token if email verification is required
    if (config.account.requireEmailVerification) {
      const verification = await createVerificationCore(ctx, {
        userId: user.id,
        type: VerificationType.COMPLETE_EMAIL_VERIFICATION,
      });

      if (!verification.success) {
        logger?.error("registerUserCore - verification creation failed", {
          requestId,
          error: verification.error.message,
          userId: user.id,
          ipAddress: req.ipAddress,
        });
        return fail(
          "REGISTER_VERIFICATION_ERROR",
          "Failed to generate verification token.",
        );
      }

      // Send verification email
      await config.email.sendEmailVerification({
        ctx,
        to: normalizedEmail,
        token: verification.data.token,
      });

      logger?.info("registerUserCore - verification email sent", {
        requestId,
        userId: user.id,
        email: normalizedEmail,
        ipAddress: req.ipAddress,
      });
    }

    logger?.info("registerUserCore - user created successfully", {
      requestId,
      userId: user.id,
      username: normalizedUsername,
      email: normalizedEmail,
      ipAddress: req.ipAddress,
      requiresVerification: config.account.requireEmailVerification,
    });

    // Return user data without the password hash
    const { passwordHash, ...rest } = user;
    return success(rest);
  } catch (error) {
    logger?.error("registerUserCore - unexpected failure", {
      requestId,
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
      ipAddress: req.ipAddress,
    });
    return fail("REGISTER_ERROR", "Failed to register user. Please try again.");
  }
}
