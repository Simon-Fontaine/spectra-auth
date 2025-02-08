import { defaultConfig } from "../src/config/default";
import { hashPassword, verifyPassword } from "../src/security/password";

describe("Password Hashing", () => {
  it("should hash and verify the password correctly", async () => {
    const password = "StrongP@ssw0rd!";
    const hash = await hashPassword({ password, config: defaultConfig });
    expect(hash).toContain(":"); // Expect the salt:key format

    const isValid = await verifyPassword({
      hash,
      password,
      config: defaultConfig,
    });
    expect(isValid).toBe(true);

    const isInvalid = await verifyPassword({
      hash,
      password: "WrongPassword",
      config: defaultConfig,
    });
    expect(isInvalid).toBe(false);
  });
});
