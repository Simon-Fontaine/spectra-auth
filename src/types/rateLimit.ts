import type { Ratelimit } from "@upstash/ratelimit";

export interface Limiters {
  login?: Ratelimit;
  register?: Ratelimit;
  verifyEmail?: Ratelimit;
  initiatePasswordReset?: Ratelimit;
  completePasswordReset?: Ratelimit;
  initiateEmailChange?: Ratelimit;
  completeEmailChange?: Ratelimit;
}
