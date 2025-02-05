(() => {
  if (!process.env.KV_REST_API_URL || !process.env.KV_REST_API_TOKEN) {
    throw new Error(
      "Upstash Redis credentials are missing (for IP-based throttling).",
    );
  }
})();

export const APP_CONFIG = {
  env: process.env.NODE_ENV || "development",
  sessionMaxAgeSec: 30 * 24 * 60 * 60, // e.g. 30 days
  sessionUpdateAgeSec: 24 * 60 * 60, // e.g. 1 day
  accountLockThreshold: 5, // # of consecutive fails
  accountLockDurationMs: 15 * 60 * 1000, // 15 minutes
};
