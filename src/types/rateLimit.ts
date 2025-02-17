import type { Ratelimit } from "@upstash/ratelimit";

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

export type EndpointName = (typeof defaultEndpoints)[number];
export type Endpoints = Partial<Record<EndpointName, Ratelimit>>;
