# Spectra Auth – Setup Guide

## Step 1: Add the Required Fields to Your Prisma Schema

In your `schema.prisma` (in your project), ensure you have at least the following fields on your `User`, `Session`, and `Verification` models:

```prisma
model User {
  id                  String   @id @default(uuid())
  email               String   @unique
  password            String
  isEmailVerified     Boolean  @default(false)
  isBanned            Boolean  @default(false)
  failedLoginAttempts Int      @default(0)
  lockedUntil         DateTime?
  // ... any other fields you want

  sessions            Session[]
  verifications       Verification[]
  // ...
}

model Session {
  id          String   @id @default(uuid())
  userId      String
  tokenPrefix String?
  tokenHash   String?
  isRevoked   Boolean  @default(false)
  expiresAt   DateTime
  // etc...

  user User @relation(fields: [userId], references: [id])
  // ...
}

model Verification {
  id        String  @id @default(uuid())
  userId    String
  token     String  @unique
  type      String  // or an enum
  expiresAt DateTime
  usedAt    DateTime?
  // ...
  
  user User @relation(fields: [userId], references: [id])
}
```
