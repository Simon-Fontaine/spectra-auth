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
  avatarUrl: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface ClientUser extends Omit<PrismaUser, "password"> {}

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

export interface ClientSession
  extends Omit<PrismaSession, "tokenHash" | "csrfTokenHash"> {
  sessionToken: string;
  csrfToken?: string;
}
