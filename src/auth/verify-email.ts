import type { PrismaClient } from "@prisma/client";
import type { AuthVerification } from "../interfaces";
import type { SpectraAuthResult } from "../types";
import { useVerificationToken } from "./verification";

/**
 * Verifies the user's email by using a token of type EMAIL_VERIFICATION.
 *
 * @param prisma - The PrismaClient instance.
 * @param token  - The raw verification token from the email link.
 * @returns      - A SpectraAuthResult with success or error details.
 */
export async function verifyEmail(
  prisma: PrismaClient,
  token: string,
): Promise<SpectraAuthResult> {
  try {
    const verification = (await useVerificationToken(prisma, {
      token,
      type: "EMAIL_VERIFICATION",
    })) as AuthVerification | null;
    if (!verification) {
      return { error: true, status: 400, message: "Invalid or expired token" };
    }

    await prisma.user.update({
      where: { id: verification.userId },
      data: { isEmailVerified: true },
    });

    return {
      error: false,
      status: 200,
      message: "Email verified.",
    };
  } catch (err) {
    return {
      error: true,
      status: 500,
      message: (err as Error).message || "Failed to verify email",
    };
  }
}
