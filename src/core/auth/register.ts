import { z } from "zod";
import { ErrorCode, RegexPatterns } from "../../constants";
import { hashPassword } from "../../security/password";
import { generateVerificationToken } from "../../security/tokens";
import type { AegisContext, AegisResponse } from "../../types";
import { createOperation } from "../../utils/error";
import { withRateLimit } from "../../utils/rate-limit";
import { fail, success } from "../../utils/response";
import { addTime } from "../../utils/time";

// Schema for registration validation
const registerSchema = z.object({
  username: z
    .string()
    .min(3, "Username must be at least 3 characters")
    .max(30, "Username cannot exceed 30 characters")
    .regex(
      RegexPatterns.USERNAME,
      "Username may only contain letters, numbers, and underscores",
    ),

  email: z
    .string()
    .email("Invalid email address")
    .transform((v) => v.toLowerCase()),

  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(64, "Password cannot exceed 64 characters")
    .regex(
      RegexPatterns.PASSWORD_HAS_LOWERCASE,
      "Password must include at least one lowercase letter",
    )
    .regex(
      RegexPatterns.PASSWORD_HAS_UPPERCASE,
      "Password must include at least one uppercase letter",
    )
    .regex(
      RegexPatterns.PASSWORD_HAS_NUMBER,
      "Password must include at least one number",
    )
    .regex(
      RegexPatterns.PASSWORD_HAS_SYMBOL,
      "Password must include at least one special character",
    ),
});

// Registration request type
export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
  invitationCode?: string;
}

// Registration response type
export interface RegisterResponse {
  userId: string;
  username: string;
  email: string;
  requiresVerification: boolean;
}

/**
 * Registers a new user
 *
 * @param ctx - Authentication context
 * @param request - Registration request data
 * @returns Response with registration result
 */
export const register = createOperation(
  "register",
  ErrorCode.REGISTER_INVALID_DATA,
  "Registration failed",
)(
  async (
    ctx: AegisContext,
    request: RegisterRequest,
  ): Promise<AegisResponse<RegisterResponse>> => {
    // Apply rate limiting
    return withRateLimit(ctx, "REGISTER", async () => {
      const { config, prisma, req } = ctx;

      // Check if registration is enabled
      if (!config.registration.enabled) {
        return fail(
          ErrorCode.REGISTER_DISABLED,
          "Registration is currently disabled",
        );
      }

      // Validate input
      const parseResult = registerSchema.safeParse(request);
      if (!parseResult.success) {
        const errorMessage =
          parseResult.error.errors[0]?.message || "Invalid registration data";

        return fail(ErrorCode.REGISTER_INVALID_DATA, errorMessage);
      }

      const { username, email, password } = parseResult.data;

      // Check for invitation if required
      if (config.registration.requireInvitation) {
        const { invitationCode } = request;

        if (!invitationCode) {
          return fail(
            ErrorCode.REGISTER_INVITATION_REQUIRED,
            "Invitation code is required for registration",
          );
        }

        const invitation = await prisma.invitation.findFirst({
          where: {
            id: invitationCode,
            email,
          },
        });

        if (!invitation) {
          return fail(
            ErrorCode.REGISTER_INVITATION_REQUIRED,
            "Invalid invitation code",
          );
        }

        if (invitation.expiresAt < new Date()) {
          return fail(
            ErrorCode.REGISTER_INVITATION_EXPIRED,
            "Invitation has expired",
          );
        }
      }

      // Check if domain is allowed (if configured)
      if (
        config.registration.allowedDomains &&
        config.registration.allowedDomains.length > 0
      ) {
        const emailDomain = email.split("@")[1];
        const isDomainAllowed = config.registration.allowedDomains.some(
          (domain) =>
            emailDomain === domain || emailDomain.endsWith(`.${domain}`),
        );

        if (!isDomainAllowed) {
          return fail(
            ErrorCode.REGISTER_INVALID_DATA,
            "Email domain not allowed for registration",
          );
        }
      }

      // Check if username or email already exists
      const existingUser = await prisma.user.findFirst({
        where: {
          OR: [{ username }, { email }],
        },
      });

      if (existingUser) {
        if (existingUser.username === username) {
          return fail(
            ErrorCode.REGISTER_USERNAME_EXISTS,
            "Username is already taken",
          );
        }

        if (existingUser.email === email) {
          return fail(
            ErrorCode.REGISTER_EMAIL_EXISTS,
            "Email is already in use",
          );
        }
      }

      // Hash the password
      const passwordHashResult = await hashPassword(password, config);
      if (!passwordHashResult.success) {
        return passwordHashResult;
      }

      // Create user with transaction to ensure consistency
      const user = await prisma.$transaction(async (tx) => {
        // Create the user
        const newUser = await tx.user.create({
          data: {
            username,
            email,
            passwordHash: passwordHashResult.data,
            isEmailVerified: !config.account.requireEmailVerification,
          },
        });

        // If using invitations, delete the used invitation
        if (config.registration.requireInvitation && request.invitationCode) {
          await tx.invitation.delete({
            where: {
              id: request.invitationCode,
            },
          });
        }

        // Add default role if available
        const defaultRole = await tx.role.findFirst({
          where: {
            name: "user",
          },
        });

        if (defaultRole) {
          await tx.userRoles.create({
            data: {
              userId: newUser.id,
              roleId: defaultRole.id,
            },
          });
        }

        return newUser;
      });

      // Send verification email if required
      if (config.account.requireEmailVerification) {
        const tokenResult = await generateVerificationToken(config);
        if (!tokenResult.success) {
          return tokenResult;
        }

        // Create verification record
        await prisma.verification.create({
          data: {
            userId: user.id,
            token: tokenResult.data,
            type: "COMPLETE_EMAIL_VERIFICATION",
            expiresAt: addTime(
              new Date(),
              config.verification.tokenExpirySeconds,
              "s",
            ),
          },
        });

        // Send verification email
        await config.email.sendEmailVerification({
          ctx,
          to: email,
          token: tokenResult.data,
        });

        ctx.config.logger?.info("Verification email sent to new user", {
          userId: user.id,
          email,
          ipAddress: req.ipAddress,
        });
      }

      ctx.config.logger?.info("User registered successfully", {
        userId: user.id,
        username,
        email,
        requiresVerification: config.account.requireEmailVerification,
        ipAddress: req.ipAddress,
      });

      return success({
        userId: user.id,
        username: user.username,
        email: user.email,
        requiresVerification: config.account.requireEmailVerification,
      });
    });
  },
);
