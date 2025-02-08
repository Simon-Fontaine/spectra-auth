import { defaultConfig } from "../src/config/default";
import {
  generateSessionToken,
  splitSessionToken,
  verifySessionToken,
} from "../src/security/sessionToken";

describe("Session Token", () => {
  it("should generate a session token and verify it correctly", async () => {
    const tokens = await generateSessionToken({ config: defaultConfig });
    expect(tokens.sessionToken).toContain(tokens.sessionPrefix);

    const split = await splitSessionToken({
      token: tokens.sessionToken,
      config: defaultConfig,
    });
    expect(split.tokenPrefix).toBe(tokens.sessionPrefix);

    // Verify the token portion against its hash.
    const tokenPart = tokens.sessionToken.split(":")[1];
    const valid = await verifySessionToken({
      token: tokenPart,
      hash: tokens.sessionTokenHash,
      config: defaultConfig,
    });
    expect(valid).toBe(true);
  });
});
