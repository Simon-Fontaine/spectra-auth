import { base64Url } from "../src/security/base64";
import { createHMAC } from "../src/security/hmac";
import {
  generateSessionToken,
  signSessionToken,
  verifySessionToken,
} from "../src/security/sessionToken";
import { createTestConfig } from "./testConfig";

jest.mock("../src/security/random", () => ({
  randomBytes: jest.fn(() => new TextEncoder().encode("testrandombytes")),
}));

jest.mock("../src/security/hmac");

describe("Session Token", () => {
  let mockConfig: ReturnType<typeof createTestConfig>;

  beforeEach(() => {
    mockConfig = createTestConfig();
    jest.clearAllMocks();

    (createHMAC as jest.Mock).mockReturnValue({
      sign: jest.fn().mockResolvedValue("testhash"),
      verify: jest.fn(),
    });
  });

  it("should generate a session token and its hash", async () => {
    const { sessionToken, sessionTokenHash } = await generateSessionToken({
      config: mockConfig,
    });

    expect(sessionToken).toBeDefined();
    expect(sessionTokenHash).toBeDefined();
    expect(sessionToken).toEqual(base64Url.encode("testrandombytes"));

    // Verify calls
    expect(createHMAC).toHaveBeenCalledWith("SHA-256", "base64urlnopad");
    const mockedHmac = (createHMAC as jest.Mock).mock.results[0].value;
    expect(mockedHmac.sign).toHaveBeenCalledWith(
      mockConfig.session.tokenSecret,
      sessionToken,
    );
  });

  it("should verify a valid session token", async () => {
    (createHMAC as jest.Mock).mockReturnValue({
      verify: jest.fn().mockResolvedValue(true),
      sign: jest.fn(),
    });

    const isValid = await verifySessionToken({
      sessionToken: "validsessiontoken",
      sessionTokenHash: "validhash",
      config: mockConfig,
    });
    expect(isValid).toBe(true);

    const mockedHmac = (createHMAC as jest.Mock).mock.results[0].value;
    expect(mockedHmac.verify).toHaveBeenCalledWith(
      mockConfig.session.tokenSecret,
      "validsessiontoken",
      "validhash",
    );
  });

  it("should not verify an invalid session token", async () => {
    (createHMAC as jest.Mock).mockReturnValue({
      verify: jest.fn().mockResolvedValue(false),
      sign: jest.fn(),
    });

    const isValid = await verifySessionToken({
      sessionToken: "invalidsessiontoken",
      sessionTokenHash: "invalidhash",
      config: mockConfig,
    });
    expect(isValid).toBe(false);
  });

  it("should sign the session token", async () => {
    const signedToken = await signSessionToken({
      sessionToken: "testsessiontoken",
      config: mockConfig,
    });
    expect(signedToken).toBe("testhash");

    const mockedHmac = (createHMAC as jest.Mock).mock.results[0].value;
    expect(mockedHmac.sign).toHaveBeenCalledWith(
      mockConfig.session.tokenSecret,
      "testsessiontoken",
    );
  });
});
