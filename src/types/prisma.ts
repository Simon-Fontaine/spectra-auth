export interface PrismaUser {
  id: string;
  username: string;
  email: string;
  passwordHash: string;
  pendingEmail: string | null;
  isEmailVerified: boolean;
  isBanned: boolean;
  failedLoginAttempts: number;
  lockedUntil: Date | null;
  avatarUrl: string | null;
  displayName: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface SessionLocation {
  country?: string | null;
  region?: string | null;
  city?: string | null;
  latitude?: number | null;
  longitude?: number | null;
}

export interface SessionDevice {
  name?: string | null;
  type?: string | null;
  browser?: string | null;
  os?: string | null;
  userAgent?: string | null;
}

export interface PrismaSession {
  id: string;
  userId: string;
  tokenHash: string;
  csrfTokenHash: string;
  isRevoked: boolean;
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
  ipAddress: string | null;
  locationData: SessionLocation | null;
  deviceData: SessionDevice | null;
}

export enum VerificationType {
  COMPLETE_EMAIL_CHANGE = "COMPLETE_EMAIL_CHANGE",
  COMPLETE_PASSWORD_RESET = "COMPLETE_PASSWORD_RESET",
  COMPLETE_EMAIL_VERIFICATION = "COMPLETE_EMAIL_VERIFICATION",
  COMPLETE_ACCOUNT_DELETION = "COMPLETE_ACCOUNT_DELETION",
}

export interface PrismaVerification {
  id: string;
  userId: string;
  token: string;
  type: VerificationType;
  metadata: Record<string, unknown> | null;
  expiresAt: Date;
  usedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface PrismaUserPasswordHistory {
  id: string;
  userId: string;
  passwordHash: string;
  createdAt: Date;
}

export interface PrismaInvitation {
  id: string;
  email: string;
  inviterId: string;
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface PrismaRole {
  id: string;
  name: string;
  permissions: string[];
}

export interface PrismaUserRole {
  id: string;
  userId: string;
  roleId: string;
}
