import type { PrismaClient } from "@prisma/client";
import { createCSRFCookie } from "../cookies";
import { generateCSRFToken, verifyCSRFToken } from "../crypto";
import type {
  AuthSession,
  SpectraAuthConfig,
  SpectraAuthResult,
} from "../types";

export async function createCSRFSecret(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  sessionToken: string,
): Promise<SpectraAuthResult> {
  if (!config.csrf.enabled)
    return {
      error: false,
      status: 200,
      message: "CSRF protection is disabled.",
    };

  const csrfSecretHash = await generateCSRFToken(
    sessionToken,
    config.session.csrfSecret,
    config,
  );

  const sessionPrefix = sessionToken.slice(
    0,
    config.session.tokenPrefixLengthBytes * 2,
  ); // Extract session prefix

  // Step 1: Find session by prefix
  const session = (await prisma.session.findFirst({
    where: { tokenPrefix: sessionPrefix },
  })) as AuthSession | null;

  if (!session) {
    config.logger.warn(
      "CSRF Cookie creation: Session not found (prefix lookup)",
      { tokenPrefix: sessionPrefix },
    );
    return {
      error: true,
      status: 403,
      message: "Invalid CSRF token.",
    };
  }

  // Step 2: Update session with CSRF secret hash
  await prisma.session.update({
    where: { id: session.id },
    data: { csrfSecret: csrfSecretHash }, // Store the HMAC hash of the CSRF token
  });

  config.logger.debug("CSRF cookie created and secret stored", {
    sessionId: session.id,
  });

  const csrfCooke = createCSRFCookie(
    csrfSecretHash,
    config.session.maxAgeSec,
    config,
  );
  return {
    error: false,
    status: 200,
    message: "CSRF secret created and stored.",
    data: {
      csrfCookie: csrfCooke,
    },
  };
}

export async function validateCSRFToken(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  options: ValidateCSRFTokenOptions,
): Promise<SpectraAuthResult> {
  if (!config.csrf.enabled) {
    return {
      error: false,
      status: 200,
      message: "CSRF protection is disabled.",
    };
  }

  const { sessionToken, csrfCookieValue, csrfSubmittedValue } = options;

  if (!sessionToken || !csrfCookieValue || !csrfSubmittedValue) {
    config.logger.warn("CSRF validation failed: missing tokens", {
      sessionToken: !!sessionToken,
      csrfCookie: !!csrfCookieValue,
      csrfSubmitted: !!csrfSubmittedValue,
    });
    return {
      error: true,
      status: 403,
      message: "Invalid CSRF token.",
    };
  }

  if (csrfCookieValue !== csrfSubmittedValue) {
    config.logger.warn(
      "CSRF validation failed: cookie and submitted token mismatch",
      { tokenPrefix: `${sessionToken.slice(0, 8)}...` },
    );
    return {
      error: true,
      status: 403,
      message: "Invalid CSRF token.",
    };
  }

  const sessionPrefix = sessionToken.slice(
    0,
    config.session.tokenPrefixLengthBytes * 2,
  );

  // Step 1: Find session by prefix
  const session = (await prisma.session.findFirst({
    where: { tokenPrefix: sessionPrefix },
  })) as AuthSession | null;

  if (!session) {
    config.logger.warn(
      "CSRF validation failed: Session not found (prefix lookup)",
      { tokenPrefix: sessionPrefix },
    );
    return {
      error: true,
      status: 403,
      message: "Invalid CSRF token.",
    };
  }

  if (!session.csrfSecret) {
    config.logger.warn(
      "CSRF validation failed: No CSRF secret found for session",
      { sessionId: session.id, tokenPrefix: sessionPrefix },
    );
    return {
      error: true,
      status: 403,
      message: "Invalid CSRF token.",
    };
  }

  // Step 2: Verify submitted CSRF token against the stored secret hash
  const isCsrfValid = await verifyCSRFToken(
    session.tokenHash || "",
    session.csrfSecret,
    csrfCookieValue,
    config.session.csrfSecret,
    config,
  );

  if (!isCsrfValid) {
    config.logger.warn("CSRF validation failed: Token verification failed", {
      sessionId: session.id,
      tokenPrefix: sessionPrefix,
    });
    return {
      error: true,
      status: 403,
      message: "Invalid CSRF token.",
    };
  }

  config.logger.debug("CSRF validation successful", {
    sessionId: session.id,
    tokenPrefix: sessionPrefix,
  });
  return {
    error: false,
    status: 200,
    message: "CSRF token is valid.",
  };
}

interface ValidateCSRFTokenOptions {
  sessionToken: string;
  csrfCookieValue: string | undefined;
  csrfSubmittedValue: string | undefined;
}
