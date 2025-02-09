import { z } from "zod";
import {
  getEmailSchema,
  getPasswordSchema,
  getUsernameSchema,
} from "./templates";

export const loginSchema = z.object({
  usernameOrEmail: z.union([getEmailSchema(), getUsernameSchema()]),
  password: getPasswordSchema("Password"),
});
