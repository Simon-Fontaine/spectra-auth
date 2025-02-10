import type { Ratelimit } from "@upstash/ratelimit";
import { limitIpAttempts } from "../src/utils/rateLimit";

// Mock @upstash/ratelimit and @upstash/redis
jest.mock("@upstash/ratelimit");
jest.mock("@upstash/redis");

describe("Rate Limiting", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should limit attempts when the rate limit is exceeded", async () => {
    const mockLimiter = {
      limit: jest.fn().mockResolvedValue({
        success: false,
        remaining: 0,
        limit: 5,
        reset: 1234567890,
      }),
    } as unknown as Ratelimit;

    const ipAddress = "127.0.0.1";
    const result = await limitIpAttempts({ ipAddress, limiter: mockLimiter });

    expect(result.success).toBe(false);
    expect(result.remaining).toBe(0);
    expect(mockLimiter.limit).toHaveBeenCalledWith(ipAddress);
  });

  it("should allow attempts when within the rate limit", async () => {
    const mockLimiter = {
      limit: jest.fn().mockResolvedValue({
        success: true,
        remaining: 4,
        limit: 5,
        reset: 1234567890,
      }),
    } as unknown as Ratelimit;

    const ipAddress = "127.0.0.1";
    const result = await limitIpAttempts({ ipAddress, limiter: mockLimiter });

    expect(result.success).toBe(true);
    expect(result.remaining).toBe(4);
    expect(mockLimiter.limit).toHaveBeenCalledWith(ipAddress);
  });
});
