import type { Ratelimit } from "@upstash/ratelimit";

export interface Endpoints {
  login?: Ratelimit;
  register?: Ratelimit;
  verifyEmail?: Ratelimit;
  initiatePasswordReset?: Ratelimit;
  completePasswordReset?: Ratelimit;
  initiateEmailChange?: Ratelimit;
  completeEmailChange?: Ratelimit;
  initiateAccountDeletion?: Ratelimit;
  completeAccountDeletion?: Ratelimit;
}

export const defaultEndpoints = [
  "login",
  "register",
  "verifyEmail",
  "initiatePasswordReset",
  "completePasswordReset",
  "initiateEmailChange",
  "completeEmailChange",
  "initiateAccountDeletion",
  "completeAccountDeletion",
] as const;
