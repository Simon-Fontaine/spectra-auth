import type { ErrorCodes } from "./errorCodes";

export interface PrismaUser {
  id: string;
  username: string;
  email: string;
  password: string;
  pendingEmail: string | null;
  isEmailVerified: boolean;
  isBanned: boolean;
  failedLoginAttempts: number;
  lockedUntil: Date | null;
  // Additional fields optional
  avatarUrl: string | null;
  displayName: string | null;
  roles: string[];
  createdAt: Date;
  updatedAt: Date;
}

export interface ClientUser extends Omit<PrismaUser, "password"> {}

export interface PrismaSession {
  id: string;
  userId: string;
  tokenHash: string;
  csrfTokenHash: string;
  isRevoked: boolean;
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
  // Optional device info
  ipAddress: string | null;
  location: string | null;
  country: string | null;
  device: string | null;
  browser: string | null;
  os: string | null;
  userAgent: string | null;
}

export interface ClientSession
  extends Omit<PrismaSession, "tokenHash" | "tokenPrefix" | "csrfTokenHash"> {
  sessionToken: string;
  csrfToken: string;
}

export interface PrismaVerification {
  id: string;
  userId: string;
  token: string;
  type:
    | "EMAIL_VERIFICATION"
    | "EMAIL_CHANGE"
    | "PASSWORD_RESET"
    | "ACCOUNT_DELETION";
  metadata: Record<string, unknown>;
  expiresAt: Date;
  usedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface ActionResponse<T = unknown> {
  success: boolean;
  status: number;
  message: string;
  code?: ErrorCodes;
  data?: T | null;
}
