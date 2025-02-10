# Aegis Auth

Aegis Auth is a secure, feature-rich authentication library for Next.js and Node.js applications. It provides everything you need to handle user authentication and session management—including user registration, login/logout, email verification, password resets, rate limiting, and CSRF protection—all while following best security practices.

> **Note:** Aegis Auth uses [Prisma](https://www.prisma.io/) for database interactions, [Upstash Redis](https://upstash.com/) for rate limiting, and [Resend](https://resend.com/) for email delivery.

## Features

- **User Registration:** Secure sign-up with input validation and duplicate user prevention.
- **User Login & Logout:** Create and revoke sessions with rate limiting and account lockout support.
- **Session Management:** Create, validate, rotate, and revoke user sessions (with rolling sessions support).
- **Password Reset:** Initiate and complete password resets using secure verification tokens.
- **Email Verification:** Verify user emails during registration or upon request using customizable email templates.
- **Rate Limiting:** Protect endpoints against abuse by limiting the number of requests per IP using Upstash Redis.
- **CSRF Protection:** Generate and verify CSRF tokens to secure state-changing requests.
- **Secure Password Hashing:** Utilizes the scrypt algorithm for password hashing.
- **Flexible Configuration:** Customize every aspect of Aegis Auth via environment variables or by passing a configuration object.

## Installation

Install the package via npm, Yarn, or pnpm:

```bash
npm install aegis-auth
# or
yarn add aegis-auth
# or
pnpm add aegis-auth
```

## Prerequisites

Before using Aegis Auth, ensure you have the following set up:

- **Node.js** (v14 or higher)
- **Database Connection:** Configure your database (PostgreSQL is supported) via the `DATABASE_URL` environment variable.
- **Upstash Redis:** For rate limiting, provide `KV_REST_API_URL` and `KV_REST_API_TOKEN` in your environment.
- **Resend API:** For email notifications, set the `RESEND_API_KEY` environment variable.
- **Environment Variables:** See the [.env.example](.env.example) file for required and optional settings.

## Configuration

Aegis Auth is highly configurable. You can override the default settings by providing a custom configuration object when you instantiate the library. For example:

```typescript
import { PrismaClient } from "@prisma/client";
import { AegisAuth } from "aegis-auth";

const prisma = new PrismaClient();

// Optionally override the default configuration
const customConfig = {
  session: {
    maxSessionsPerUser: 3, // Limit the number of concurrent sessions per user
  },
  accountSecurity: {
    requireEmailVerification: true, // Force email verification on registration
  },
  // ...other custom settings
};

const auth = new AegisAuth(prisma, customConfig);
```

You can also configure most options via environment variables. See the provided `.env.example`:

```dotenv
SESSION_TOKEN_SECRET="change-me-in-prod"
CSRF_SECRET="change-me-in-prod"
KV_REST_API_URL="https://..."
KV_REST_API_TOKEN="..."
DATABASE_URL="your_database_connection_string"
NODE_ENV="development"
RESEND_API_KEY="your-resend-api-key"
EMAIL_FROM="no-reply@yourdomain.com"
```

For a full list of configuration options, refer to the [configuration schema](./src/config/schema.ts).

## Usage

### Initializing Aegis Auth

To begin using Aegis Auth, import it along with your Prisma client and instantiate the class:

```typescript
import { PrismaClient } from "@prisma/client";
import { AegisAuth } from "aegis-auth";

const prisma = new PrismaClient();
const auth = new AegisAuth(prisma);
```

### Registering a New User

```typescript
// Example: Register a new user
const registrationResult = await auth.registerUser(
  { headers: request.headers },
  {
    username: "john_doe",
    email: "john@example.com",
    password: "SecurePassword123!",
  }
);

if (registrationResult.success) {
  console.log("User registered:", registrationResult.data.user);
} else {
  console.error("Registration error:", registrationResult.message);
}
```

### Logging In

```typescript
// Example: Log in a user
const loginResult = await auth.loginUser(
  { headers: request.headers },
  {
    usernameOrEmail: "john@example.com",
    password: "SecurePassword123!",
  }
);

if (loginResult.success) {
  const { user, session } = loginResult.data;
  console.log("Login successful for:", user);
  // Use session.sessionToken to set your session cookie
} else {
  console.error("Login failed:", loginResult.message);
}
```

### Managing Sessions

Aegis Auth provides methods to handle sessions automatically:

- **Session Creation:** Performed during login.
- **Session Validation & Rotation:** Use `validateAndRotateSession` to verify and refresh sessions.
- **Logout:** Revoke the current session.

```typescript
// Example: Log out a user
const logoutResult = await auth.logoutUser({
  sessionToken: "user_session_token",
});

if (logoutResult.success) {
  console.log("User logged out successfully");
} else {
  console.error("Logout error:", logoutResult.message);
}
```

### Password Reset

#### Initiate Password Reset

```typescript
// Initiate the password reset process (sends an email with a verification token)
const initiateResult = await auth.initiatePasswordReset(
  { headers: request.headers },
  { email: "john@example.com" }
);
console.log(initiateResult.message);
```

#### Complete Password Reset

```typescript
// Complete the password reset using the token sent via email
const completeResult = await auth.completePasswordReset(
  { headers: request.headers },
  {
    token: "verification_token_from_email",
    newPassword: "NewSecurePassword123!",
  }
);

if (completeResult.success) {
  console.log("Password reset successful");
} else {
  console.error("Password reset error:", completeResult.message);
}
```

### Email Verification

When email verification is enabled, a verification email is sent upon registration. To verify the email:

```typescript
const verificationResult = await auth.verifyEmail(
  { headers: request.headers },
  { token: "verification_token_from_email" }
);

if (verificationResult.success) {
  console.log("Email verified successfully");
} else {
  console.error("Email verification failed:", verificationResult.message);
}
```

## Testing

Aegis Auth includes a comprehensive suite of tests using Jest. To run the tests:

```bash
npm test
```

## Development

To build the project, run:

```bash
npm run build
```

Lint your code with:

```bash
npm run lint
```

## Security

Security is a top priority. If you discover any vulnerabilities, please refer to our [SECURITY.md](SECURITY.md) for instructions on reporting issues.

## License

Aegis Auth is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For questions, support, or contributions, please open an issue on [GitHub](https://github.com/Simon-Fontaine/aegis-auth) or email [github@simonfontaine.com](mailto:github@simonfontaine.com).

---

Happy coding!
