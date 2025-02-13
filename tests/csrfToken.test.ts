import { base64Url } from "../src/security/base64";
import { generateCsrfToken, verifyCsrfToken } from "../src/security/csrfToken";
import { createHMAC } from "../src/security/hmac";
import { createTestConfig } from "./testConfig";

jest.mock("../src/security/random", () => ({
  randomBytes: jest.fn(() => new TextEncoder().encode("testrandombytescsrf")),
}));

jest.mock("../src/security/hmac");

describe("CSRF Token", () => {
  let mockConfig: ReturnType<typeof createTestConfig>;

  beforeEach(() => {
    // Create a fresh config for each test so tests won't affect each other
    mockConfig = createTestConfig();

    jest.clearAllMocks();
    (createHMAC as jest.Mock).mockReturnValue({
      sign: jest.fn().mockResolvedValue("csrfTestHash"),
      verify: jest.fn(),
    });
  });

  it("should generate a CSRF token and its hash", async () => {
    const { csrfToken, csrfTokenHash } = await generateCsrfToken({
      config: mockConfig,
    });

    expect(csrfToken).toBeDefined();
    expect(csrfTokenHash).toBeDefined();

    // The randomBytes mock returns "testrandombytescsrf",
    // so we expect the token to be the base64Url-encoded version of that.
    expect(csrfToken).toEqual(base64Url.encode("testrandombytescsrf"));
    expect(csrfTokenHash).toEqual("csrfTestHash");

    // Verify that createHMAC().sign was called with the right args
    expect(createHMAC).toHaveBeenCalledWith("SHA-256", "base64urlnopad");
    const mockedHmac = (createHMAC as jest.Mock).mock.results[0].value;
    expect(mockedHmac.sign).toHaveBeenCalledWith(
      mockConfig.csrf.tokenSecret,
      csrfToken,
    );
  });

  it("should verify a valid CSRF token", async () => {
    (createHMAC as jest.Mock).mockReturnValue({
      verify: jest.fn().mockResolvedValue(true),
      sign: jest.fn(),
    });

    const isValid = await verifyCsrfToken({
      token: "validcsrftoken",
      hash: "validcsrfhash",
      config: mockConfig,
    });
    expect(isValid).toBe(true);

    const mockedHmac = (createHMAC as jest.Mock).mock.results[0].value;
    expect(mockedHmac.verify).toHaveBeenCalledWith(
      mockConfig.csrf.tokenSecret,
      "validcsrftoken",
      "validcsrfhash",
    );
  });

  it("should reject an invalid CSRF token", async () => {
    (createHMAC as jest.Mock).mockReturnValue({
      verify: jest.fn().mockResolvedValue(false),
      sign: jest.fn(),
    });

    const isValid = await verifyCsrfToken({
      token: "somecsrftoken",
      hash: "somecsrfhash",
      config: mockConfig,
    });
    expect(isValid).toBe(false);
  });
});
