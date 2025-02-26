import { z } from "zod";
import { ErrorCode } from "../../constants";
import { verifyPassword } from "../../security/password";
import { createSession } from "../../security/session";
import type { AegisContext, AegisResponse, AuthCookies } from "../../types";
import { createOperation } from "../../utils/error";
import { withRateLimit } from "../../utils/rate-limit";
import { fail, success } from "../../utils/response";
import { createTime } from "../../utils/time";

// Input validation schema
const loginSchema = z.object({
  usernameOrEmail: z.string().min(1, "Username or email is required"),
  password: z.string().min(1, "Password is required"),
});

// Login request type
export interface LoginRequest {
  usernameOrEmail: string;
  password: string;
}

// Login response type
export interface LoginResponse {
  userId: string;
  cookies: AuthCookies;
}

/**
 * Authenticates a user with username/email and password
 *
 * @param ctx - Authentication context
 * @param request - Login request data
 * @returns Response with authentication result
 */
export const login = createOperation(
  "login",
  ErrorCode.AUTH_INVALID_CREDENTIALS,
  "Authentication failed",
)(
  async (
    ctx: AegisContext,
    request: LoginRequest,
  ): Promise<AegisResponse<LoginResponse>> => {
    // Apply rate limiting
    return withRateLimit(ctx, "login", async () => {
      const { config, prisma, req } = ctx;

      // Validate input
      const parseResult = loginSchema.safeParse(request);
      if (!parseResult.success) {
        return fail(
          ErrorCode.AUTH_INVALID_CREDENTIALS,
          "Invalid username or password",
        );
      }

      const { usernameOrEmail, password } = parseResult.data;

      // Find user by username or email
      const user = await prisma.user.findFirst({
        where: {
          OR: [{ username: usernameOrEmail }, { email: usernameOrEmail }],
        },
        include: {
          passwordHistory: {
            orderBy: { createdAt: "desc" },
            take: 5,
          },
        },
      });

      // Use constant-time operations to prevent timing attacks
      if (!user) {
        // Simulate password verification to prevent timing attacks
        await verifyPassword("dummy-password", "dummy:dummy", config);

        ctx.config.logger?.warn("Login attempt with non-existent user", {
          usernameOrEmail,
          ipAddress: req.ipAddress,
        });

        return fail(
          ErrorCode.AUTH_INVALID_CREDENTIALS,
          "Invalid username or password",
        );
      }

      // Check if user is banned
      if (user.isBanned) {
        ctx.config.logger?.warn("Login attempt for banned user", {
          userId: user.id,
          ipAddress: req.ipAddress,
        });

        return fail(ErrorCode.AUTH_USER_BANNED, "This account has been banned");
      }

      // Check account lockout
      if (user.lockedUntil && user.lockedUntil > new Date()) {
        const remainingTime = createTime(
          user.lockedUntil.getTime() - Date.now(),
          "ms",
        );

        ctx.config.logger?.warn("Login attempt for locked account", {
          userId: user.id,
          lockedUntil: user.lockedUntil.toISOString(),
          ipAddress: req.ipAddress,
        });

        return fail(
          ErrorCode.AUTH_USER_LOCKED,
          `Account is locked. Try again ${remainingTime.fromNow()}`,
        );
      }

      // Add exponential backoff delay for repeated failures
      if (user.failedLoginAttempts > 0) {
        const delayMs = Math.min(
          2000, // Cap at 2 seconds max
          2 ** Math.min(user.failedLoginAttempts, 10) * 100,
        );
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }

      // Verify password
      const passwordValid = await verifyPassword(
        password,
        user.passwordHash,
        config,
      );

      // Handle invalid password
      if (!passwordValid.success || !passwordValid.data) {
        const updatedAttempts = user.failedLoginAttempts + 1;

        // Check if account should be locked
        let lockUntil: Date | null = null;

        if (updatedAttempts >= config.login.maxFailedAttempts) {
          // Use exponential backoff for lockout duration
          const lockoutFactor = Math.min(
            3, // Cap at 3x the configured duration
            1 + Math.floor(updatedAttempts / config.login.maxFailedAttempts),
          );

          const lockoutDuration = createTime(
            config.login.lockoutDurationSeconds * lockoutFactor,
            "s",
          );

          lockUntil = lockoutDuration.getDate();

          ctx.config.logger?.warn(
            "Account locked due to failed login attempts",
            {
              userId: user.id,
              failedAttempts: updatedAttempts,
              lockedUntil: lockUntil.toISOString(),
              ipAddress: req.ipAddress,
            },
          );
        }

        // Update failed login attempts
        await prisma.user.update({
          where: { id: user.id },
          data: {
            failedLoginAttempts: updatedAttempts,
            lockedUntil: lockUntil,
          },
        });

        // Return error
        if (lockUntil) {
          const lockoutTime = createTime(
            lockUntil.getTime() - Date.now(),
            "ms",
          );

          return fail(
            ErrorCode.AUTH_USER_LOCKED,
            `Account is locked. Try again ${lockoutTime.fromNow()}`,
          );
        }

        return fail(
          ErrorCode.AUTH_INVALID_CREDENTIALS,
          "Invalid username or password",
        );
      }

      // Check if email verification is required
      if (!user.isEmailVerified && config.account.requireEmailVerification) {
        ctx.config.logger?.warn("Login attempt for unverified email", {
          userId: user.id,
          ipAddress: req.ipAddress,
        });

        return fail(
          ErrorCode.AUTH_EMAIL_NOT_VERIFIED,
          "Please verify your email address before logging in",
        );
      }

      // Reset failed login attempts and lockout
      if (user.failedLoginAttempts > 0 || user.lockedUntil) {
        await prisma.user.update({
          where: { id: user.id },
          data: {
            failedLoginAttempts: 0,
            lockedUntil: null,
          },
        });
      }

      // Create session
      const sessionResult = await createSession(prisma, config, {
        userId: user.id,
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      if (!sessionResult.success) {
        return sessionResult;
      }

      ctx.config.logger?.info("User logged in successfully", {
        userId: user.id,
        ipAddress: req.ipAddress,
      });

      return success({
        userId: user.id,
        cookies: sessionResult.data.cookies,
      });
    });
  },
);
