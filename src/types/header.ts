export type AuthHeaders =
  | Headers
  | { get: (key: string) => string | null | undefined };
