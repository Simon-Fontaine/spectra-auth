import { VerificationType } from "@prisma/client";
import { z } from "zod";
import type { AegisAuthConfig } from "../config";
import {
  getEmailSchema,
  getPasswordSchema,
  getUsernameSchema,
} from "./templates";

export const banUserSchema = z.object({
  userId: z.string().min(1),
});

export const completeEmailChangeSchema = z.object({
  token: z.string().min(1),
});

export const completePasswordResetSchema = (config: AegisAuthConfig) =>
  z.object({
    token: z.string().min(1),
    newPassword: getPasswordSchema(
      "Password",
      config.accountSecurity.passwordPolicy,
    ),
  });

export const createSessionSchema = z.object({
  userId: z.string().min(1),
});

export const createVerificationSchema = z.object({
  userId: z.string().min(1),
  type: z.nativeEnum(VerificationType),
  tokenExpirySeconds: z.number().int().positive().optional(),
});

export const initiateEmailChangeSchema = z.object({
  userId: z.string().min(1),
  newEmail: getEmailSchema(),
});

export const initiatePasswordResetSchema = z.object({
  email: getEmailSchema(),
});

export const loginSchema = (config: AegisAuthConfig) =>
  z.object({
    usernameOrEmail: z.union([getEmailSchema(), getUsernameSchema()]),
    password: getPasswordSchema(
      "Password",
      config.accountSecurity.passwordPolicy,
    ),
  });

export const logoutUserSchema = z.object({
  sessionToken: z.string().min(1),
});

export const registerSchema = (config: AegisAuthConfig) =>
  z.object({
    username: getUsernameSchema(),
    email: getEmailSchema(),
    password: getPasswordSchema(
      "Password",
      config.accountSecurity.passwordPolicy,
    ),
  });

export const revokeAllSessionsForUserSchema = z.object({
  userId: z.string().min(1),
});

export const revokeSessionSchema = z.object({
  sessionToken: z.string().min(1),
});

export const unbanUserSchema = z.object({
  userId: z.string().min(1),
});

export const updateUserRolesSchema = z.object({
  userId: z.string().min(1),
  roles: z.array(z.string().min(1)),
});

export const useVerificationTokenSchema = z.object({
  token: z.string().min(1),
  type: z.nativeEnum(VerificationType),
});

export const validateAndRotateSessionSchema = z.object({
  sessionToken: z.string().min(1),
});

export const verifyEmailSchema = z.object({
  token: z.string().min(1),
});
