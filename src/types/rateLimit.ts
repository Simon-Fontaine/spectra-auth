import type { Ratelimit } from "@upstash/ratelimit";

export type Limiters = {
  login?: Ratelimit;
  register?: Ratelimit;
  verifyEmail?: Ratelimit;
  forgotPassword?: Ratelimit;
  passwordReset?: Ratelimit;
};
