import { z } from "zod";
import { verifyPassword } from "../security";
import type { AegisContext, AegisResponse, PasswordConfig } from "../types";
import {
  type TimeObject,
  createSession,
  createTime,
  fail,
  getGeolocation,
  limitIpAddress,
  success,
} from "../utils";
import {
  getEmailSchema,
  getPasswordSchema,
  getUsernameSchema,
} from "../validations";

interface LoginRequest {
  usernameOrEmail: string;
  password: string;
}

interface LoginResponse {
  userId: string;
  cookies: string[];
}

const schema = (policy: PasswordConfig["rules"]) =>
  z.object({
    usernameOrEmail: z.union([getEmailSchema(), getUsernameSchema()]),
    password: getPasswordSchema("Password", policy),
  });

export async function loginUserCore(
  ctx: AegisContext,
  options: LoginRequest,
): Promise<AegisResponse<LoginResponse>> {
  const { config, prisma, req, endpoints } = ctx;
  const { logger } = config;
  const requestId = Math.random().toString(36).substring(2, 15);

  logger?.debug("loginUserCore - invoked", {
    requestId,
    usernameOrEmail: options.usernameOrEmail,
    ipAddress: req.ipAddress,
  });

  try {
    // Input validation
    const parsed = schema(config.password.rules).safeParse(options);
    if (!parsed.success) {
      logger?.debug("loginUserCore - validation error", {
        requestId,
        error: parsed.error.issues,
        ipAddress: req.ipAddress,
      });
      return fail("LOGIN_INVALID_REQUEST", "Invalid username or password.");
    }
    const { usernameOrEmail, password } = parsed.data;

    // Rate limiting
    if (config.rateLimit.endpoints.login?.enabled && req.ipAddress) {
      const limiter = endpoints.login;
      if (!limiter) {
        logger?.error("loginUserCore - rate-limit endpoint missing", {
          requestId,
          ipAddress: req.ipAddress,
        });
        return fail(
          "LOGIN_RATE_LIMIT_ERROR",
          "Server misconfiguration. Please try again later.",
        );
      }
      const limit = await limitIpAddress(req.ipAddress, limiter);
      if (!limit.success) {
        logger?.warn("loginUserCore - rate limit exceeded", {
          requestId,
          ipAddress: req.ipAddress,
        });
        return fail(
          "LOGIN_RATE_LIMIT_EXCEEDED",
          "Too many requests. Please try again later.",
        );
      }
    }

    // Find user
    const userRecord = await prisma.user.findFirst({
      where: {
        OR: [{ email: usernameOrEmail }, { username: usernameOrEmail }],
      },
      include: {
        userRoles: { include: { role: true } },
        sessions: true,
        passwordHistory: true,
      },
    });

    if (!userRecord) {
      logger?.warn("loginUserCore - user not found", {
        requestId,
        usernameOrEmail,
        ipAddress: req.ipAddress,
      });

      // Implement constant-time handling regardless of user existence
      // This helps prevent timing attacks that could determine if a username exists
      await verifyPassword({
        hash: "dummy:dummy", // Use dummy hash with same format
        password,
        config,
      });

      return fail(
        "LOGIN_INVALID_CREDENTIALS",
        "Username or password is incorrect.",
      );
    }

    // Check user status
    if (userRecord.isBanned) {
      logger?.warn("loginUserCore - Banned user attempted login", {
        requestId,
        userId: userRecord.id,
      });
      return fail("LOGIN_BANNED_USER", "This account is currently banned.");
    }

    // Check account lockout
    const now = new Date();
    if (userRecord.lockedUntil && userRecord.lockedUntil > now) {
      const lockedUntilTime = createTime(
        userRecord.lockedUntil.getTime(),
        "ms",
      );
      logger?.warn("loginUserCore - account locked", {
        requestId,
        userId: userRecord.id,
        lockedUntil: userRecord.lockedUntil.toISOString(),
      });
      return fail(
        "LOGIN_USER_LOCKED_OUT",
        `Account is locked. Try again ${lockedUntilTime.fromNow()}.`,
      );
    }

    // Add exponential backoff delay for repeated failures
    // This adds an increasing delay with each failed attempt to slow down brute force attacks
    if (userRecord.failedLoginAttempts > 0) {
      const delayMs = Math.min(
        2000, // Cap at 2 seconds max
        2 ** Math.min(userRecord.failedLoginAttempts, 10) * 100,
      );
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }

    // Verify password
    const pwCheck = await verifyPassword({
      hash: userRecord.passwordHash,
      password,
      config,
    });

    if (!pwCheck.success || !pwCheck.data) {
      const updatedAttempts = userRecord.failedLoginAttempts + 1;
      logger?.warn("loginUserCore - password mismatch", {
        requestId,
        userId: userRecord.id,
        attempts: updatedAttempts,
      });

      let newLockedUntil: TimeObject | null = null;
      let lockUser = false;

      if (updatedAttempts >= config.login.maxFailedAttempts) {
        lockUser = true;
        // Use exponential backoff for lockout duration
        const lockoutFactor = Math.min(
          3, // Cap at 3x the configured duration
          1 + Math.floor(updatedAttempts / config.login.maxFailedAttempts),
        );
        const lockoutDuration =
          config.login.lockoutDurationSeconds * lockoutFactor;
        newLockedUntil = createTime(lockoutDuration, "s");
      }

      await prisma.user.update({
        where: { id: userRecord.id },
        data: {
          failedLoginAttempts: updatedAttempts,
          lockedUntil: lockUser ? newLockedUntil?.getDate() : null,
        },
      });

      if (lockUser) {
        logger?.warn("loginUserCore - user locked out", {
          requestId,
          userId: userRecord.id,
          attempts: updatedAttempts,
        });
        return fail(
          "LOGIN_USER_LOCKED_OUT",
          `Account is locked. Try again ${newLockedUntil?.fromNow()}.`,
        );
      }

      return fail(
        "LOGIN_INVALID_CREDENTIALS",
        "Username or password is incorrect.",
      );
    }

    // Reset failed login attempts and lockout if successful
    if (userRecord.failedLoginAttempts > 0 || userRecord.lockedUntil) {
      await prisma.user.update({
        where: { id: userRecord.id },
        data: {
          failedLoginAttempts: 0,
          lockedUntil: null,
        },
      });
    }

    // Check email verification if required
    if (
      !userRecord.isEmailVerified &&
      config.account.requireEmailVerification
    ) {
      logger?.warn("loginUserCore - email not verified", {
        requestId,
        userId: userRecord.id,
      });
      return fail(
        "LOGIN_EMAIL_NOT_VERIFIED",
        "Please verify your email address before logging in.",
      );
    }

    // Get geolocation data
    const geoResp = await getGeolocation(config, req.ipAddress, req.userAgent);
    if (!geoResp.success || !geoResp.data) {
      logger?.warn("loginUserCore - geolocation failed", {
        requestId,
        userId: userRecord.id,
        error: geoResp.error?.message,
      });
      return fail(
        "LOGIN_GEO_LOOKUP_ERROR",
        "Location data unavailable. Please try again later.",
      );
    }

    // Create session
    const { sessionCookie, csrfCookie } = await createSession(
      prisma,
      config,
      userRecord.id,
      req.ipAddress,
      geoResp.data.locationData,
      geoResp.data.deviceData,
      req.headers,
    );

    // Log successful login
    logger?.info("loginUserCore - User login successful", {
      requestId,
      userId: userRecord.id,
      ipAddress: req.ipAddress,
      userAgent: req.userAgent?.substring(0, 100),
      geoCountry: geoResp.data.locationData?.country,
    });

    return success({
      userId: userRecord.id,
      cookies: [sessionCookie, csrfCookie],
    });
  } catch (error) {
    logger?.error("loginUserCore - failed unexpectedly", {
      requestId,
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
      ipAddress: req.ipAddress,
    });
    return fail("LOGIN_ERROR", "An unexpected error occurred during login.");
  }
}
