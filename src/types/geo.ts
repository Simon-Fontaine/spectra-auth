export interface SessionLocation {
  [key: string]: string | number | null | undefined;
  country?: string | null;
  region?: string | null;
  city?: string | null;
  latitude?: number | null;
  longitude?: number | null;
}

export interface SessionDevice {
  [key: string]: string | null | undefined;
  name?: string | null;
  type?: string | null;
  browser?: string | null;
  os?: string | null;
  userAgent?: string | null;
}
