import { hashPassword, verifyPassword } from "../src/security/password";
import { createTestConfig } from "./testConfig";

describe("Password Hashing", () => {
  let mockConfig: ReturnType<typeof createTestConfig>;

  beforeEach(() => {
    mockConfig = createTestConfig();
  });

  it("should hash a password and produce a salt:key format", async () => {
    const password = "TestPassword1!";
    const hashedPassword = await hashPassword({ password, config: mockConfig });

    expect(hashedPassword).toBeDefined();
    // The format is "salt:key"
    expect(hashedPassword).toContain(":");
    const [salt, key] = hashedPassword.split(":");
    expect(salt).toBeTruthy();
    expect(key).toBeTruthy();
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
      password: "WrongPassword",
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

    // Confirm it rejects any other password
    const isInvalid = await verifyPassword({
      hash: hashedPassword,
      password: "NotEmpty",
      config: mockConfig,
    });
    expect(isInvalid).toBe(false);
  });
});
