import { configSchema } from "../src/config/schema";

export function createTestConfig() {
  return configSchema.parse({
    session: {},
    csrf: {},
    verification: {},
    rateLimiting: {
      login: {},
      register: {},
      verifyEmail: {},
      initiatePasswordReset: {},
      completePasswordReset: {},
      initiateEmailChange: {},
      completeEmailChange: {},
    },
    accountSecurity: {
      passwordHashing: {},
      passwordPolicy: {},
    },
    email: {},
  });
}
