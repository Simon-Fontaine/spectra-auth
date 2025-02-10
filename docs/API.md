# Aegis Auth API Documentation

Aegis Auth provides a robust set of functions to handle user authentication and related security flows such as registration, login, session management, password resets, and email verification. This document describes the available methods, their parameters, and expected responses.

## Table of Contents

1. [Initialization](#initialization)
2. [Methods](#methods)
    - [registerUser](#registeruser)
    - [loginUser](#loginuser)
    - [logoutUser](#logoutuser)
    - [initiatePasswordReset](#initiatepasswordreset)
    - [completePasswordReset](#completepasswordreset)
    - [verifyEmail](#verifyemail)
    - [validateAndRotateSession](#validateandrotatesession)
    - [revokeSession](#revokesession)
    - [createSession](#createsession)
    - [createVerification](#createverification)
    - [useVerificationToken](#useverificationtoken)
3. [Response Format](#response-format)
4. [Additional Notes](#additional-notes)

---

## Initialization

Before using any of the API methods, instantiate the `AegisAuth` class with your Prisma client and an optional configuration object:

```typescript
import { PrismaClient } from "@prisma/client";
import { AegisAuth } from "aegis-auth";

const prisma = new PrismaClient();
const auth = new AegisAuth(prisma, {
  // Override defaults if needed
});
```

---

## Methods

### registerUser

**Purpose:** Registers a new user account. If email verification is required, a verification token is generated and (optionally) emailed to the user.

**Signature:**

```typescript
async registerUser(options: {
  input: {
    username: string;
    email: string;
    password: string;
  };
  ipAddress?: string;
  headers?: Record<string, string>; // Added for CSRF
}): Promise<ActionResponse<{ user: ClientUser }>>;
```

**Example:**

```typescript
const result = await auth.registerUser({
  options: {
    input: {
      username: "johndoe",
      email: "john@example.com",
      password: "SecureP@ss123!",
    },
    ipAddress: "192.168.1.1",
    headers: req.headers as Record<string, string>, // Pass headers from the request
  },
});

if (result.success) {
  console.log("User registered", result.data?.user);
} else {
  console.error("Registration error:", result.message);
}
```

---

### loginUser

**Purpose:** Authenticates a user by validating their credentials and, on success, creates a new session.  **Important:** This function now also verifies the CSRF token.

**Signature:**

```typescript
async loginUser(options: {
  input: {
    usernameOrEmail: string;
    password: string;
  };
  ipAddress?: string;
  userAgent?: string;
  headers?: Record<string, string>; // Added for CSRF
}): Promise<ActionResponse<{ user: ClientUser; session: ClientSession }>>;
```

**Example:**

```typescript
const result = await auth.loginUser({
  options: {
    input: {
      usernameOrEmail: "johndoe",
      password: "SecureP@ss123!",
    },
    ipAddress: "192.168.1.1",
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
    headers: req.headers as Record<string, string>, // Pass headers from the request
  },
});

if (result.success) {
  console.log("Login successful", result.data?.user);
    // Important: Set both session and CSRF cookies in the response headers.
} else {
  console.error("Login failed:", result.message);
}
```

---

### logoutUser

**Purpose:** Logs out the user by revoking the provided session token.

**Signature:**

```typescript
async logoutUser(sessionToken: string): Promise<ActionResponse>;
```

**Example:**

```typescript
const result = await auth.logoutUser("fullSessionTokenHere");

if (result.success) {
  console.log("Logout successful");
} else {
  console.error("Logout failed:", result.message);
}
```

---

### initiatePasswordReset

**Purpose:** Begins the password reset process by generating a verification token and (optionally) sending a password reset email.

**Signature:**

```typescript
async initiatePasswordReset(options: {
  input: {
    email: string;
  };
  ipAddress?: string;
}): Promise<ActionResponse>;
```

**Example:**

```typescript
const result = await auth.initiatePasswordReset({
  options: {
    input: {
      email: "john@example.com",
    },
    ipAddress: "192.168.1.1",
  },
});

console.log(result.message); // Should indicate an email was sent (if configured)
```

---

### completePasswordReset

**Purpose:** Completes the password reset process by verifying the reset token and updating the user's password.  All active sessions for the user are revoked.

**Signature:**

```typescript
async completePasswordReset(options: {
  input: {
    token: string;
    newPassword: string;
  };
  ipAddress?: string;
}): Promise<ActionResponse>;
```

**Example:**

```typescript
const result = await auth.completePasswordReset({
  options: {
    input: {
      token: "reset-token-here",
      newPassword: "NewSecureP@ss123!",
    },
    ipAddress: "192.168.1.1",
  },
});

console.log(result.message);
```

---

### verifyEmail

**Purpose:** Verifies a user's email address by consuming a verification token.

**Signature:**

```typescript
async verifyEmail(options: {
  input: {
    token: string;
  };
  ipAddress?: string;
}): Promise<ActionResponse>;
```

**Example:**

```typescript
const result = await auth.verifyEmail({
  options: {
    input: {
      token: "email-verification-token",
    },
    ipAddress: "192.168.1.1",
  },
});

console.log(result.message);
```

---

### validateAndRotateSession

**Purpose:** Validates a session token and, if the session's rolling interval has passed, rolls (replaces) the session with a new one.  This is typically called on every request that requires authentication.

**Signature:**

```typescript
async validateAndRotateSession(options: {
  input: {
    sessionToken: string;
  };
}): Promise<ActionResponse<{ session?: ClientSession; rolled: boolean }>>;
```

**Example:**

```typescript
const result = await auth.validateAndRotateSession({
  options: {
    input: {
      sessionToken: "fullSessionTokenHere",
    },
  },
});

if (result.success) {
  if (result.data?.rolled) {
    console.log("Session was rolled", result.data.session);
    // Important: Set new session and CSRF cookies in the response headers.
  } else {
    console.log("Session is valid");
  }
} else {
  console.error("Session validation failed:", result.message);
}
```

---

### revokeSession

**Purpose:** Revokes a session, marking it as invalid.  This function is used internally but can also be called directly.

**Signature:**

```typescript
async revokeSession(options: {
  input: {
    sessionToken: string;
  };
}): Promise<ActionResponse>;
```

**Example:**

```typescript
const result = await auth.revokeSession({
  options: {
    input: {
      sessionToken: "fullSessionTokenHere",
    },
  },
});

console.log(result.message);
```

---

### createSession

**Purpose:** Creates a new session for a user, generating secure session and CSRF tokens. This method enforces the maximum number of concurrent sessions per user.  **Note:** This function is generally used internally by `loginUser` and `validateAndRotateSession`.

**Signature:**

```typescript
async createSession(options: {
  userId: string;
  ipAddress?: string;
  location?: string;
  country?: string;
  device?: string;
  browser?: string;
  os?: string;
  userAgent?: string;
}): Promise<ActionResponse<{ session: ClientSession }>>;
```

**Example:**

```typescript
const result = await auth.createSession({
    options: {
        userId: "user-id-here",
        ipAddress: "192.168.1.1",
        device: "Desktop",
        browser: "Chrome",
    }
});

if (result.success && result.data?.session) {
  console.log("Session created", result.data.session);
  // Important: Set both session and CSRF cookies in the response headers.
}
```

---

### createVerification

**Purpose:** Generates a verification token (for email verification, password reset, etc.) and saves it to the database.  **Note:** This function is generally used internally.

**Signature:**

```typescript
async createVerification(options: {
  userId: string;
  type: "EMAIL_VERIFICATION" | "PASSWORD_RESET" | "ACCOUNT_DELETION" | "EMAIL_CHANGE";
  tokenExpirySeconds?: number;
}): Promise<ActionResponse<{ verification: PrismaVerification }>>;
```

**Example:**

```typescript
const result = await auth.createVerification({
    options: {
        userId: "user-id-here",
        type: "EMAIL_VERIFICATION"
    }
});

if (result.success && result.data?.verification) {
  console.log("Verification token created", result.data.verification.token);
}
```

---

### useVerificationToken

**Purpose:** Consumes a verification token by verifying its validity and marking it as used (to prevent reuse).  **Note:** This function is generally used internally.

**Signature:**

```typescript
async useVerificationToken(options: {
  input: {
    token: string;
    type: "EMAIL_VERIFICATION" | "PASSWORD_RESET" | "ACCOUNT_DELETION" | "EMAIL_CHANGE";
  };
}): Promise<ActionResponse<{ verification: PrismaVerification }>>;
```

**Example:**

```typescript
const result = await auth.useVerificationToken({
  options: {
      input: {
        token: "verification-token-here",
        type: "PASSWORD_RESET",
      }
  }
});

if (result.success) {
  console.log("Verification token validated");
} else {
  console.error("Token validation failed:", result.message);
}
```

---

## Response Format

All methods return a standardized response conforming to the `ActionResponse<T>` interface:

```typescript
interface ActionResponse<T = unknown> {
  success: boolean;      // Indicates whether the action succeeded
  status: number;       // HTTP-like status code
  message: string;       // A descriptive message
  code?: string;        // Optional error code for failures
  data?: T | null;      // Payload (e.g., user, session, verification details)
}
```

---

## Additional Notes

- **IP Address & User Agent:** Many methods accept an optional `ipAddress` and `userAgent` parameter to improve rate limiting and logging accuracy.
- **Error Handling:** Always check the `success` property and handle errors using the provided `message` and (optionally) the `code` field.
- **Security Considerations:** Ensure all secrets and configurations are managed securely via environment variables.  Verify that rate limiting and session policies are properly enforced in production.  Always set both session and CSRF cookies appropriately.  Use the dedicated CSRF token endpoint to provide tokens to client-side frameworks.
- **Cookie Handling:** This library provides helper functions in `src/cookies` (e.g., `createSessionCookie`, `clearSessionCookie`, `createCsrfCookie`, `clearCsrfCookie`, `getCsrfToken`, `getSessionToken`) to manage cookies securely. Use these functions to interact with cookies. You'll need to use a library like the `cookie` npm package to serialize the cookies for setting them in your responses (see the Usage Examples in the README).
