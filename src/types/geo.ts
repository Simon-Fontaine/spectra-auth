export interface SessionLocation {
  country?: string | null;
  region?: string | null;
  city?: string | null;
  latitude?: number | null;
  longitude?: number | null;
}

export interface SessionDevice {
  name?: string | null;
  type?: string | null;
  browser?: string | null;
  os?: string | null;
  userAgent?: string | null;
}
