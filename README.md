# Spectra Auth

A credentials-based authentication solution for Next.js (and other Node.js projects) featuring:

- **Database-backed sessions** (stored in Prisma)
- **IP rate-limiting** (powered by [Upstash Redis](https://upstash.com/))
- **Automatic account lockouts** after too many failed attempts
- **Email verification** and **password reset** flows

## Table of Contents

1. [Installation](#installation)
2. [Prerequisites](#prerequisites)
3. [Prisma Schema Setup](#prisma-schema-setup)
4. [Environment Variables](#environment-variables)
5. [Usage Example](#usage-example)
6. [Available Methods](#available-methods)
7. [License](#license)

---

## Installation

```bash
npm install spectra-auth

# or, if you prefer Yarn or pnpm:
# yarn add spectra-auth
# pnpm add spectra-auth
```

---

## Prerequisites

- **Prisma**: You need a Prisma setup (including your `schema.prisma`) to store users, sessions, and verification records.
- **Upstash Redis**: For IP-based rate-limiting, you need an Upstash Redis database (or similar). Spectra Auth uses environment variables to connect.

---

## Prisma Schema Setup

In your `schema.prisma`, ensure you have the following (or equivalent) models. (Spectra Auth expects these fields to exist, but you can add more fields if needed.)

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
  // Additional fields are optional
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

After updating your schema, run:

```bash
npx prisma db push
# or
npx prisma migrate dev
```

---

## Environment Variables

Spectra Auth uses Upstash for IP-based rate-limiting. Set the following environment variables:

```bash
# .env
KV_REST_API_URL="<YOUR_UPSTASH_REDIS_REST_URL>"
KV_REST_API_TOKEN="<YOUR_UPSTASH_REDIS_TOKEN>"

# optional: production environment
NODE_ENV="production"
```

- **`KV_REST_API_URL`** and **`KV_REST_API_TOKEN`** are **required** for rate-limiting.
- **`NODE_ENV`** is used to determine security options for cookies and other environment-specific logic (defaults to `"development"` if not specified).

---

## Usage Example

Below is a minimal example using Prisma and Express-like pseudocode to demonstrate basic login and registration.

```ts
// src/server.ts
import express from "express";
import { PrismaClient } from "@prisma/client";
import { initSpectraAuth } from "spectra-auth";

const app = express();
app.use(express.json());

const prisma = new PrismaClient();

// Initialize Spectra Auth
const auth = initSpectraAuth(prisma);

// ======================
//   Register Endpoint
// ======================
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  const result = await auth.registerUser({
    username,
    email,
    password,
  });

  if (result.error) {
    return res.status(result.status).json({ message: result.message });
  }

  // Registration success
  res.status(result.status).json({
    message: result.message,
    data: result.data,
  });
});

// ======================
//   Login Endpoint
// ======================
app.post("/login", async (req, res) => {
  const { identifier, password } = req.body;

  // Typically retrieve IP from the request
  const ipAddress = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

  const loginResult = await auth.loginUser({
    input: { identifier, password },
    ipAddress: String(ipAddress),
    deviceInfo: {
      browser: req.headers["user-agent"],
    },
  });

  if (loginResult.error) {
    return res.status(loginResult.status).json({ message: loginResult.message });
  }

  // Extract the raw token from result.data
  const rawToken = loginResult.data?.rawToken;

  // Ideally, you'd set a HTTP-only cookie containing the session token
  // In production, set 'secure: true' and other best practices
  res.cookie("spectra.session", rawToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  });

  res.status(loginResult.status).json({
    message: loginResult.message,
    userId: loginResult.data?.userId,
  });
});

// ======================
//   Protected Endpoint
// ======================
app.get("/profile", async (req, res) => {
  // Suppose we parse the raw token from cookies:
  const rawToken = req.cookies["spectra.session"];
  if (!rawToken) {
    return res.status(401).json({ message: "No session token provided" });
  }

  const sessionCheck = await auth.validateSession(rawToken);
  if (sessionCheck.error) {
    return res.status(sessionCheck.status).json({ message: sessionCheck.message });
  }

  // If valid, sessionCheck.data contains the session + user info
  res.status(200).json({
    message: "Session is valid!",
    session: sessionCheck.data?.session,
  });
});

// ======================
//   Logout Endpoint
// ======================
app.post("/logout", async (req, res) => {
  const rawToken = req.cookies["spectra.session"];
  if (!rawToken) {
    return res.status(401).json({ message: "No session token provided" });
  }

  const result = await auth.logoutUser(rawToken);
  if (result.error) {
    return res.status(result.status).json({ message: result.message });
  }

  // Clear the cookie
  res.clearCookie("spectra.session");
  res.status(result.status).json({ message: result.message });
});

// Start server
app.listen(3000, () => {
  console.log("Server listening on http://localhost:3000");
});
```

---

## Available Methods

When you call `const auth = initSpectraAuth(prisma)`, you get an object with these methods:

1. **Registration**
   - `registerUser({ username, email, password })`

2. **Login / Logout**
   - `loginUser({ input: {identifier, password}, ipAddress, deviceInfo })`
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

Each method returns a **`SpectraAuthResult`** object:

```ts
interface SpectraAuthResult {
  error: boolean;
  status: number;
  message: string;
  data?: Record<string, unknown>;
}
```

---

## License

[MIT License](./LICENSE) © 2025 [Simon Fontaine](https://github.com/Simon-Fontaine)
