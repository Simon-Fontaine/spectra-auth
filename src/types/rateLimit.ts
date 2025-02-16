import type { Ratelimit } from "@upstash/ratelimit";

export interface Endpoints {
  login?: Ratelimit;
  register?: Ratelimit;
  verifyEmail?: Ratelimit;
  initiatePasswordReset?: Ratelimit;
  completePasswordReset?: Ratelimit;
  initiateEmailChange?: Ratelimit;
  completeEmailChange?: Ratelimit;
}

export const defaultEndpoints = [
  "login",
  "register",
  "verifyEmail",
  "initiatePasswordReset",
  "completePasswordReset",
  "initiateEmailChange",
  "completeEmailChange",
] as const;
