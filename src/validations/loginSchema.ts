import { z } from "zod";

export const loginSchema = z.object({
  usernameOrEmail: z.string().nonempty(),
  password: z.string().nonempty(),
});
