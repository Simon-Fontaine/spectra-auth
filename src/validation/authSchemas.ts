import { z } from "zod";

const passwordPolicy = z
  .string()
  .min(8, "Must be at least 8 characters")
  .regex(/[A-Z]/, "Requires uppercase")
  .regex(/[a-z]/, "Requires lowercase")
  .regex(/[0-9]/, "Requires a digit")
  .regex(/[^A-Za-z0-9]/, "Requires a special character");

export const registerSchema = z.object({
  username: z.string().min(3).max(30),
  email: z.string().email(),
  password: passwordPolicy,
});

export const loginSchema = z.object({
  identifier: z.string().nonempty(),
  password: z.string().nonempty(),
});
