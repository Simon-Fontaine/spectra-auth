import { defaultConfig } from "../src/config";
import { base64Url } from "../src/security/base64";
import { generateCsrfToken, verifyCsrfToken } from "../src/security/csrfToken";
import { createHMAC } from "../src/security/hmac";

jest.mock("../src/security/random", () => ({
  randomBytes: jest.fn(() => Buffer.from("testrandombytescsrf")),
}));

jest.mock("../src/security/hmac"); // Mock the hmac functions

describe("CSRF Token", () => {
  const mockConfig = {
    ...defaultConfig,
    csrf: { ...defaultConfig.csrf, tokenSecret: "csrfTestSecret" },
  };

  beforeEach(() => {
    jest.clearAllMocks(); // Clear mock calls before each test
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
    expect(csrfToken).toEqual(base64Url.encode("testrandombytescsrf"));
    expect(csrfTokenHash).toEqual("csrfTestHash");

    // Verify that randomBytes and createHMAC were called
    expect(require("../src/security/random").randomBytes).toHaveBeenCalledWith(
      mockConfig.csrf.tokenLengthBytes,
    );
    expect(createHMAC).toHaveBeenCalledWith("SHA-256", "base64urlnopad");
    const mockedHmac = (createHMAC as jest.Mock).mock.results[0].value;
    expect(mockedHmac.sign).toHaveBeenCalledWith(
      mockConfig.csrf.tokenSecret,
      csrfToken,
    );
  });

  it("should verify a valid CSRF token", async () => {
    const csrfToken = "validcsrftoken";
    const csrfTokenHash = "validcsrfhash";
    (createHMAC as jest.Mock).mockReturnValue({
      verify: jest.fn().mockResolvedValue(true), // Mock verify to return true
      sign: jest.fn().mockResolvedValue("csrfTestHash"),
    });

    const isValid = await verifyCsrfToken({
      token: csrfToken,
      hash: csrfTokenHash,
      config: mockConfig,
    });
    expect(isValid).toBe(true);
    const mockedHmac = (createHMAC as jest.Mock).mock.results[0].value;
    expect(mockedHmac.verify).toHaveBeenCalledWith(
      mockConfig.csrf.tokenSecret,
      csrfToken,
      csrfTokenHash,
    );
  });

  it("should reject an invalid CSRF token", async () => {
    const csrfToken = "validcsrftoken";
    const csrfTokenHash = "validcsrfhash";
    (createHMAC as jest.Mock).mockReturnValue({
      verify: jest.fn().mockResolvedValue(false), // Mock verify to return true
      sign: jest.fn().mockResolvedValue("csrfTestHash"),
    });

    const isValid = await verifyCsrfToken({
      token: csrfToken,
      hash: csrfTokenHash,
      config: mockConfig,
    });

    expect(isValid).toBe(false);
    const mockedHmac = (createHMAC as jest.Mock).mock.results[0].value;
    expect(mockedHmac.verify).toHaveBeenCalledWith(
      mockConfig.csrf.tokenSecret,
      csrfToken,
      csrfTokenHash,
    );
  });
});
