import { defaultConfig } from "../src/config/default";
import { base64Url } from "../src/security/base64";
import { createHMAC } from "../src/security/hmac"; // Import createHMAC
import {
  generateSessionToken,
  signSessionToken,
  verifySessionToken,
} from "../src/security/sessionToken";

jest.mock("../src/security/random", () => ({
  randomBytes: jest.fn(() => Buffer.from("testrandombytes")),
}));

jest.mock("../src/security/hmac"); // Mock the hmac functions

describe("Session Token", () => {
  const mockConfig = {
    ...defaultConfig,
    session: { ...defaultConfig.session, tokenSecret: "testsecret" },
  };

  beforeEach(() => {
    jest.clearAllMocks(); // Clear mock calls before each test
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

    // Verify that randomBytes and createHMAC were called correctly
    expect(require("../src/security/random").randomBytes).toHaveBeenCalledWith(
      mockConfig.session.tokenLengthBytes,
    );
    expect(createHMAC).toHaveBeenCalledWith("SHA-256", "base64urlnopad");
    const mockedHmac = (createHMAC as jest.Mock).mock.results[0].value; // Access the mocked hmac object.
    expect(mockedHmac.sign).toHaveBeenCalledWith(
      mockConfig.session.tokenSecret,
      sessionToken,
    );
  });

  it("should verify a valid session token", async () => {
    const sessionToken = "validsessiontoken";
    const sessionTokenHash = "validhash";

    (createHMAC as jest.Mock).mockReturnValue({
      verify: jest.fn().mockResolvedValue(true), // Mock verify to return true
      sign: jest.fn().mockResolvedValue("testhash"),
    });
    const isValid = await verifySessionToken({
      sessionToken,
      sessionTokenHash,
      config: mockConfig,
    });
    expect(isValid).toBe(true);
    const mockedHmac = (createHMAC as jest.Mock).mock.results[0].value;
    expect(mockedHmac.verify).toHaveBeenCalledWith(
      mockConfig.session.tokenSecret,
      sessionToken,
      sessionTokenHash,
    );
  });

  it("should not verify an invalid session token", async () => {
    const sessionToken = "invalidsessiontoken";
    const sessionTokenHash = "invalidhash";
    (createHMAC as jest.Mock).mockReturnValue({
      verify: jest.fn().mockResolvedValue(false), // Mock verify to return false
      sign: jest.fn().mockResolvedValue("testhash"),
    });

    const isValid = await verifySessionToken({
      sessionToken,
      sessionTokenHash,
      config: mockConfig,
    });

    expect(isValid).toBe(false);
    const mockedHmac = (createHMAC as jest.Mock).mock.results[0].value;
    expect(mockedHmac.verify).toHaveBeenCalledWith(
      mockConfig.session.tokenSecret,
      sessionToken,
      sessionTokenHash,
    );
  });

  it("should sign the session token", async () => {
    const sessionToken = "testsessiontoken";
    const signedToken = await signSessionToken({
      sessionToken,
      config: mockConfig,
    });
    expect(signedToken).toEqual("testhash");
    const mockedHmac = (createHMAC as jest.Mock).mock.results[0].value;
    expect(mockedHmac.sign).toHaveBeenCalledWith(
      mockConfig.session.tokenSecret,
      sessionToken,
    );
  });
});
