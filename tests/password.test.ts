import { defaultConfig } from "../src/config/default";
import { hashPassword, verifyPassword } from "../src/security/password";

describe("Password Hashing", () => {
  const mockConfig = defaultConfig; // Or customize for specific test cases

  it("should hash a password and produce a salt:key format", async () => {
    const password = "TestPassword1!";
    const hashedPassword = await hashPassword({ password, config: mockConfig });

    expect(hashedPassword).toBeDefined();
    expect(hashedPassword).toContain(":"); // Check for the expected format

    const [salt, key] = hashedPassword.split(":");
    expect(salt).toBeDefined();
    expect(key).toBeDefined();
  });

  it("should verify a password against its hash", async () => {
    const password = "AnotherTestPassword2!";
    const hashedPassword = await hashPassword({ password, config: mockConfig });

    const isValid = await verifyPassword({
      hash: hashedPassword,
      password,
      config: mockConfig,
    });
    expect(isValid).toBe(true);
  });

  it("should reject an incorrect password", async () => {
    const password = "CorrectPassword3!";
    const hashedPassword = await hashPassword({ password, config: mockConfig });

    const isValid = await verifyPassword({
      hash: hashedPassword,
      password: "IncorrectPassword",
      config: mockConfig,
    });
    expect(isValid).toBe(false);
  });

  it("should handle empty password", async () => {
    const password = "";
    const hashedPassword = await hashPassword({ password, config: mockConfig });
    const isValid = await verifyPassword({
      hash: hashedPassword,
      password,
      config: mockConfig,
    });
    expect(isValid).toBe(true);

    const isInvalid = await verifyPassword({
      hash: hashedPassword,
      password: "WrongPassword",
      config: mockConfig,
    });
    expect(isInvalid).toBe(false);
  });
});
