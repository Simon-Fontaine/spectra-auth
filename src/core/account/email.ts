import type { Prisma, VerificationType } from "@prisma/client";
import { z } from "zod";
import { Endpoints, ErrorCode } from "../../constants";
import { generateVerificationToken } from "../../security/tokens";
import type {
  AegisContext,
  AegisResponse,
  AuthenticatedUser,
} from "../../types";
import { createOperation } from "../../utils/error";
import { withRateLimit } from "../../utils/rate-limit";
import { fail, success } from "../../utils/response";
import { addTime } from "../../utils/time";

// Email verification endpoints

/**
 * Initiates email verification by sending a verification link
 */
export const initiateEmailVerification = createOperation(
  "initiateEmailVerification",
  ErrorCode.EMAIL_VERIFICATION_INVALID,
  "Failed to initiate email verification",
)(async (ctx: AegisContext): Promise<AegisResponse<boolean>> => {
  return withRateLimit(ctx, Endpoints.VERIFY_EMAIL, async () => {
    const { config, prisma, auth, req } = ctx;

    // Check if user is authenticated
    if (!auth.isAuthenticated || !auth.user) {
      return fail(
        ErrorCode.AUTH_NOT_AUTHENTICATED,
        "You must be logged in to verify your email",
      );
    }

    // Check if email is already verified
    if (auth.user.isEmailVerified) {
      return fail(
        ErrorCode.EMAIL_VERIFICATION_INVALID,
        "Your email is already verified",
      );
    }

    // Generate verification token
    const tokenResult = await generateVerificationToken(config);
    if (!tokenResult.success) {
      return tokenResult;
    }

    // Create verification record
    await prisma.verification.create({
      data: {
        userId: auth.user.id,
        token: tokenResult.data,
        type: "COMPLETE_EMAIL_VERIFICATION" as VerificationType,
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
      to: auth.user.email,
      token: tokenResult.data,
    });

    ctx.config.logger?.info("Verification email sent", {
      userId: auth.user.id,
      email: auth.user.email,
      ipAddress: req.ipAddress,
    });

    return success(true);
  });
});

/**
 * Completes email verification using a verification token
 */
export const completeEmailVerification = createOperation(
  "completeEmailVerification",
  ErrorCode.EMAIL_VERIFICATION_INVALID,
  "Failed to verify email",
)(async (ctx: AegisContext, token: string): Promise<AegisResponse<boolean>> => {
  return withRateLimit(ctx, Endpoints.VERIFY_EMAIL, async () => {
    const { config, prisma, req } = ctx;

    // Find verification record
    const verification = await prisma.verification.findUnique({
      where: { token },
    });

    // Verify token validity
    if (!verification) {
      return fail(
        ErrorCode.EMAIL_VERIFICATION_INVALID,
        "Invalid verification token",
      );
    }

    // Check token type
    if (verification.type !== "COMPLETE_EMAIL_VERIFICATION") {
      return fail(
        ErrorCode.VERIFICATION_TYPE_MISMATCH,
        "Invalid verification type",
      );
    }

    // Check if token is expired
    if (verification.expiresAt < new Date()) {
      return fail(
        ErrorCode.EMAIL_VERIFICATION_EXPIRED,
        "Verification token has expired",
      );
    }

    // Check if token is already used
    if (verification.usedAt) {
      return fail(
        ErrorCode.EMAIL_VERIFICATION_USED,
        "Verification token has already been used",
      );
    }

    // Update user as verified
    await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
      // Mark user as verified
      await tx.user.update({
        where: { id: verification.userId },
        data: { isEmailVerified: true },
      });

      // Mark verification as used
      await tx.verification.update({
        where: { id: verification.id },
        data: { usedAt: new Date() },
      });
    });

    ctx.config.logger?.info("Email verified successfully", {
      userId: verification.userId,
      ipAddress: req.ipAddress,
    });

    return success(true);
  });
});

// Email change endpoints

// Request schema
const changeEmailSchema = z.object({
  newEmail: z
    .string()
    .email("Invalid email address")
    .transform((v) => v.toLowerCase()),
});

/**
 * Initiates email change process
 */
export const initiateEmailChange = createOperation(
  "initiateEmailChange",
  ErrorCode.EMAIL_CHANGE_INVALID,
  "Failed to initiate email change",
)(
  async (
    ctx: AegisContext,
    newEmail: string,
  ): Promise<AegisResponse<boolean>> => {
    return withRateLimit(ctx, Endpoints.INITIATE_EMAIL_CHANGE, async () => {
      const { config, prisma, auth, req } = ctx;

      // Check if user is authenticated
      if (!auth.isAuthenticated || !auth.user) {
        return fail(
          ErrorCode.AUTH_NOT_AUTHENTICATED,
          "You must be logged in to change your email",
        );
      }

      // Validate new email
      const parseResult = changeEmailSchema.safeParse({ newEmail });
      if (!parseResult.success) {
        return fail(
          ErrorCode.EMAIL_CHANGE_INVALID,
          parseResult.error.errors[0]?.message || "Invalid email format",
        );
      }

      const validatedEmail = parseResult.data.newEmail;

      // Check if new email is different from current
      if (auth.user.email.toLowerCase() === validatedEmail.toLowerCase()) {
        return fail(
          ErrorCode.EMAIL_CHANGE_SAME_EMAIL,
          "New email is the same as your current email",
        );
      }

      // Check if email is already in use
      const existingUser = await prisma.user.findFirst({
        where: {
          OR: [{ email: validatedEmail }, { pendingEmail: validatedEmail }],
        },
      });

      if (existingUser) {
        return fail(
          ErrorCode.EMAIL_CHANGE_IN_USE,
          "This email is already in use by another account",
        );
      }

      // Generate verification token
      const tokenResult = await generateVerificationToken(config);
      if (!tokenResult.success) {
        return tokenResult;
      }

      // Save pending email and create verification
      await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
        // Update user with pending email
        await tx.user.update({
          where: { id: (auth.user as AuthenticatedUser).id },
          data: { pendingEmail: validatedEmail },
        });

        // Create verification record
        await tx.verification.create({
          data: {
            userId: (auth.user as AuthenticatedUser).id,
            token: tokenResult.data,
            type: "COMPLETE_EMAIL_CHANGE" as VerificationType,
            expiresAt: addTime(
              new Date(),
              config.verification.tokenExpirySeconds,
              "s",
            ),
            metadata: { newEmail: validatedEmail } as Prisma.InputJsonValue,
          },
        });
      });

      // Send verification email to new address
      await config.email.sendEmailChange({
        ctx,
        to: validatedEmail,
        token: tokenResult.data,
      });

      ctx.config.logger?.info("Email change initiated", {
        userId: auth.user.id,
        currentEmail: auth.user.email,
        newEmail: validatedEmail,
        ipAddress: req.ipAddress,
      });

      return success(true);
    });
  },
);

/**
 * Completes email change process using verification token
 */
export const completeEmailChange = createOperation(
  "completeEmailChange",
  ErrorCode.EMAIL_CHANGE_INVALID,
  "Failed to change email",
)(async (ctx: AegisContext, token: string): Promise<AegisResponse<boolean>> => {
  return withRateLimit(ctx, Endpoints.COMPLETE_EMAIL_CHANGE, async () => {
    const { config, prisma, req } = ctx;

    // Find verification record
    const verification = await prisma.verification.findUnique({
      where: { token },
      include: { user: true },
    });

    // Verify token validity
    if (!verification) {
      return fail(ErrorCode.EMAIL_CHANGE_INVALID, "Invalid verification token");
    }

    // Check token type
    if (verification.type !== "COMPLETE_EMAIL_CHANGE") {
      return fail(
        ErrorCode.VERIFICATION_TYPE_MISMATCH,
        "Invalid verification type",
      );
    }

    // Check if token is expired
    if (verification.expiresAt < new Date()) {
      return fail(
        ErrorCode.EMAIL_CHANGE_INVALID,
        "Verification token has expired",
      );
    }

    // Check if token is already used
    if (verification.usedAt) {
      return fail(
        ErrorCode.EMAIL_CHANGE_INVALID,
        "Verification token has already been used",
      );
    }

    // Extract new email from metadata
    const metadata = verification.metadata as { newEmail?: string } | null;
    const newEmail = metadata?.newEmail || verification.user.pendingEmail;

    if (!newEmail) {
      return fail(
        ErrorCode.EMAIL_CHANGE_INVALID,
        "No pending email change found",
      );
    }

    // Verify email is not taken since verification was created
    const existingUser = await prisma.user.findFirst({
      where: {
        email: newEmail,
        id: { not: verification.userId },
      },
    });

    if (existingUser) {
      return fail(
        ErrorCode.EMAIL_CHANGE_IN_USE,
        "This email is now in use by another account",
      );
    }

    // Update user email
    await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
      // Update user email
      await tx.user.update({
        where: { id: verification.userId },
        data: {
          email: newEmail,
          pendingEmail: null,
        },
      });

      // Mark verification as used
      await tx.verification.update({
        where: { id: verification.id },
        data: { usedAt: new Date() },
      });
    });

    ctx.config.logger?.info("Email changed successfully", {
      userId: verification.userId,
      newEmail: newEmail,
      ipAddress: req.ipAddress,
    });

    return success(true);
  });
});
