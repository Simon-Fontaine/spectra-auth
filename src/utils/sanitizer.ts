import type {
  ClientSession,
  ClientUser,
  PrismaSession,
  PrismaUser,
} from "../types";

export function clientSafeUser({ user }: { user: PrismaUser }): ClientUser {
  const { password, ...safeUser } = user;
  return safeUser;
}

export function clientSafeSession({
  session,
  sessionToken,
  csrfToken,
}: {
  session: PrismaSession;
  sessionToken: string;
  csrfToken: string;
}): ClientSession {
  const { csrfTokenHash, tokenHash, tokenPrefix, ...safeSession } = session;
  const clientSession = {
    ...safeSession,
    sessionToken,
    csrfToken,
  };
  return clientSession;
}
