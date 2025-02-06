export function validateEnv() {
  if (!process.env.KV_REST_API_URL) {
    throw new Error("Missing KV_REST_API_URL in environment variables.");
  }
  if (!process.env.KV_REST_API_TOKEN) {
    throw new Error("Missing KV_REST_API_TOKEN in environment variables.");
  }
}
