# Spectra Auth

A **credentials-based** authentication solution for Next.js (and other Node.js projects) featuring:

- **Database-backed sessions** (stored in [Prisma](https://www.prisma.io/))
- **IP rate-limiting** (powered by [Upstash Redis](https://upstash.com/))
- **Automatic account lockouts** after too many failed attempts
- **Email verification** and **password reset** flows
- Designed to integrate easily with **your own Prisma schema**, with minimal required fields

## Table of Contents

1. [Installation](#installation)  
2. [Prerequisites](#prerequisites)  
3. [Prisma Schema Setup](#prisma-schema-setup)  
4. [Environment Variables](#environment-variables)  
5. [Usage Example](#usage-example)  
6. [Available Methods](#available-methods)  
7. [Testing](#testing)  
8. [License](#license)

## 1. Installation

```bash
npm install spectra-auth

# or:
yarn add spectra-auth
pnpm add spectra-auth
```

## 2. Prerequisites

- **Prisma**: You need Prisma configured in your project to store `User`, `Session`, and `Verification` data.  
- **Upstash Redis**: Required for IP-based rate-limiting. If you don’t plan to use rate-limiting, you can mock or disable it in tests, but in production, you should set it up.

## 3. Prisma Schema Setup

In your `schema.prisma`, ensure you have the following (or equivalent) models. Spectra Auth expects at least these fields, though you can add more. If you rename fields, you may need to adapt some logic:

```prisma
enum VerificationType {
  EMAIL_VERIFICATION
  PASSWORD_RESET
  ACCOUNT_DELETION
  EMAIL_CHANGE
}

model User {
  id                  String    @id @default(uuid())
  username            String    @unique
  email               String    @unique
  password            String
  isEmailVerified     Boolean   @default(false)
  isBanned            Boolean   @default(false)
  failedLoginAttempts Int       @default(0)
  lockedUntil         DateTime?
  // Additional fields optional
  displayName         String?
  roles               String[]
  createdAt           DateTime  @default(now())
  updatedAt           DateTime  @updatedAt

  sessions      Session[]
  verifications Verification[]

  @@map("users")
}

model Session {
  id          String   @id @default(uuid())
  userId      String
  tokenPrefix String?
  tokenHash   String?
  isRevoked   Boolean  @default(false)
  expiresAt   DateTime
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
  // Optional device info:
  ipAddress   String?
  location    String?
  country     String?
  device      String?
  browser     String?
  userAgent   String?

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@index([tokenPrefix])
  @@map("sessions")
}

model Verification {
  id        String           @id @default(uuid())
  userId    String
  token     String           @unique
  type      VerificationType
  metadata  Json?
  expiresAt DateTime
  usedAt    DateTime?
  createdAt DateTime         @default(now())
  updatedAt DateTime         @updatedAt

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("verifications")
}
```

Once updated, run:

```bash
npx prisma db push
# or:
npx prisma migrate dev
```

## 4. Environment Variables

Spectra Auth uses Upstash for IP-based rate-limiting. You must set these environment variables so the library won’t complain at load time:

```bash
# .env
UPSTASH_REDIS_REST_URL="<YOUR_UPSTASH_REDIS_REST_URL>"
UPSTASH_REDIS_REST_TOKEN="<YOUR_UPSTASH_REDIS_TOKEN>"

# Optional:
NODE_ENV="production"
```

- **`UPSTASH_REDIS_REST_URL`** and **`UPSTASH_REDIS_REST_TOKEN`** are **required** if you’re actually using rate-limiting in production.  

## 5. Usage Example

Below is a minimal example using **Express**-style pseudocode. The same logic applies in Next.js or any Node environment:

```ts
// src/server.ts
import express from "express";
import { PrismaClient } from "@prisma/client";
import { initSpectraAuth, createSessionCookie, clearSessionCookie, getSessionTokenFromHeader } from "spectra-auth";

const app = express();
app.use(express.json());

const prisma = new PrismaClient();
const auth = initSpectraAuth(prisma);

// Login endpoint
app.post("/login", async (req, res) => {
  const { identifier, password } = req.body;
  const ipAddress = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

  const result = await auth.loginUser({
    input: { identifier, password },
    ipAddress: String(ipAddress),
  });

  if (result.error) {
    return res.status(result.status).json({ message: result.message });
  }

  // Suppose result.data.rawToken is the session token.
  const rawToken = result.data?.rawToken as string;

  // Here we use createSessionCookie from the library
  const cookieStr = createSessionCookie(rawToken, 30 * 24 * 60 * 60); // 30 days

  // Return a Set-Cookie header. In Express, you can do res.setHeader or res.set.
  res.setHeader("Set-Cookie", cookieStr);

  res.status(result.status).json({
    message: result.message,
    userId: result.data?.userId,
  });
});

// Protected route example
app.get("/profile", async (req, res) => {
  // Retrieve the raw token from the Cookie header using your helper
  const rawToken = getSessionTokenFromHeader(req.headers.cookie ?? null);
  if (!rawToken) {
    return res.status(401).json({ message: "No session token provided" });
  }

  const sessionCheck = await auth.validateSession(rawToken);
  if (sessionCheck.error) {
    return res.status(sessionCheck.status).json({ message: sessionCheck.message });
  }

  res.status(200).json({
    message: "Session is valid",
    session: sessionCheck.data?.session,
  });
});

// Logout endpoint
app.post("/logout", async (req, res) => {
  const rawToken = getSessionTokenFromHeader(req.headers.cookie ?? null);
  if (!rawToken) {
    return res.status(401).json({ message: "No session token found" });
  }

  // Revoke the session in DB
  const result = await auth.logoutUser(rawToken);
  if (result.error) {
    return res.status(result.status).json({ message: result.message });
  }

  // Clear the session cookie
  const clearStr = clearSessionCookie();
  res.setHeader("Set-Cookie", clearStr);

  res.status(result.status).json({ message: "Logged out" });
});

app.listen(3000, () => {
  console.log("Server listening on http://localhost:3000");
});
```

## 6. Available Methods

When you call `initSpectraAuth(prisma)`, you get an object with these methods:

1. **Registration**  
   - `registerUser({ username, email, password })`
2. **Login / Logout**  
   - `loginUser({ input: {identifier, password}, ipAddress?, deviceInfo? })`  
   - `logoutUser(rawToken)`
3. **Session Management**  
   - `createSession({ userId, deviceInfo })`
   - `validateSession(rawToken)`
   - `revokeSession(rawToken)`
4. **Email Verification**  
   - `createVerificationToken({ userId, type, expiresIn? })`
   - `useVerificationToken({ token, type })`
   - `verifyEmail(rawToken)`
5. **Password Reset**  
   - `initiatePasswordReset(email)`
   - `completePasswordReset({ token, newPassword })`

Each returns a **`SpectraAuthResult`**:

```ts
interface SpectraAuthResult {
  error: boolean;
  status: number;
  message: string;
  data?: Record<string, unknown>;
}
```

## 7. License

[MIT License](./LICENSE) © 2025 [Simon Fontaine](https://github.com/Simon-Fontaine)
