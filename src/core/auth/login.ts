import { z } from "zod";
import { ErrorCode } from "../../constants";
import { verifyPassword } from "../../security/password";
import { createSession } from "../../security/session";
import type {
  AegisAuthConfig,
  AegisContext,
  AegisResponse,
  AuthCookies,
} from "../../types";
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
 * Calculates progressive lockout duration
 */
function calculateLockoutDuration(
  attempts: number,
  baseSeconds: number,
): number {
  // At least 1 minute lockout initially
  const minLockoutSeconds = 60;

  // For first few attempts, use shorter lockouts
  if (attempts <= 3) {
    return Math.max(minLockoutSeconds, (baseSeconds * attempts) / 3);
  }

  // For repeated failures, increase exponentially with a reasonable cap (24 hours)
  const maxLockoutSeconds = 24 * 60 * 60;

  // Exponential backoff: baseSeconds * 2^(attempts - threshold)
  const duration = baseSeconds * 2 ** (attempts - 3);

  return Math.min(duration, maxLockoutSeconds);
}

/**
 * Tracks suspicious IP addresses in Redis
 */
async function trackSuspiciousIP(
  ipAddress: string,
  userId: string,
  attempts: number,
  config: AegisAuthConfig,
): Promise<void> {
  // Skip if Redis rate limiting is not available
  if (!config.rateLimit.enabled || !config.rateLimit.redis) {
    return;
  }

  try {
    // Use Redis to track suspicious IPs
    const redis = config.rateLimit.redis;
    const key = `${config.rateLimit.prefix}:suspicious_ip:${ipAddress}`;

    // Store IP with user ID and failure count
    await redis.set(
      key,
      JSON.stringify({
        ipAddress,
        userId,
        attempts,
        lastAttempt: new Date().toISOString(),
      }),
    );

    // Set expiry (keep for 24 hours)
    await redis.expire(key, 24 * 60 * 60);

    // If attempts reach a threshold, add to a high-risk IP set
    if (attempts >= 10) {
      await redis.sadd(`${config.rateLimit.prefix}:high_risk_ips`, ipAddress);
      // Keep this set for 7 days
      await redis.expire(
        `${config.rateLimit.prefix}:high_risk_ips`,
        7 * 24 * 60 * 60,
      );
    }
  } catch (error) {
    // Log but don't fail the login process
    config.logger?.error("Failed to track suspicious IP", {
      ipAddress,
      userId,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

/**
 * Authenticates a user with username/email and password
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
    return withRateLimit(ctx, "LOGIN", async () => {
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
          // Use progressive lockout duration
          const lockoutDurationSeconds = calculateLockoutDuration(
            updatedAttempts,
            config.login.lockoutDurationSeconds,
          );

          const lockoutDuration = createTime(lockoutDurationSeconds, "s");
          lockUntil = lockoutDuration.getDate();

          // Track suspicious IP if available
          if (req.ipAddress) {
            await trackSuspiciousIP(
              req.ipAddress,
              user.id,
              updatedAttempts,
              config,
            );
          }

          // Send security alert for excessive failed attempts
          if (
            config.email.sendSecurityAlert &&
            updatedAttempts >= config.login.maxFailedAttempts * 2
          ) {
            try {
              await config.email.sendSecurityAlert({
                ctx,
                to: user.email,
                subject: "Suspicious login activity detected",
                activityType: "failed_login",
                metadata: {
                  attempts: updatedAttempts,
                  ipAddress: req.ipAddress,
                  userAgent: req.userAgent,
                  lockedUntil: lockUntil.toISOString(),
                },
              });
            } catch (error) {
              // Log but continue
              ctx.config.logger?.error("Failed to send security alert", {
                userId: user.id,
                error: error instanceof Error ? error.message : String(error),
              });
            }
          }

          ctx.config.logger?.warn(
            "Account locked due to failed login attempts",
            {
              userId: user.id,
              username: user.username,
              email: user.email,
              failedAttempts: updatedAttempts,
              lockoutDurationSeconds,
              lockedUntil: lockUntil.toISOString(),
              ipAddress: req.ipAddress,
              userAgent: req.userAgent?.substring(0, 100),
              timestamp: new Date().toISOString(),
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
