export const maskIpAddress = (ip: string): string => {
  if (ip.includes(":")) {
    const groups = ip.split(":").filter(Boolean);
    return groups.length > 1 ? `${groups.slice(0, 2).join(":")}:••••` : "••••";
  }
  const parts = ip.split(".");
  return parts.length === 4 ? `${parts[0]}.${parts[1]}.•••.•••` : "••••";
};

export const locationLabel = (
  country: string,
  region: string,
  city: string,
): string => [city, region, country].filter(Boolean).join(", ");

export const uptimeLabel = (milliseconds: number): string => {
  const seconds = Math.max(0, Math.floor(milliseconds / 1000));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainder = seconds % 60;
  return [hours, minutes, remainder]
    .map((value) => String(value).padStart(2, "0"))
    .join(":");
};

/** A displayable core version, or null when the host has no real version to report. */
export const coreVersionLabel = (raw: string | undefined | null): string | null => {
  const match = raw?.trim().match(/^v?(\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?)$/);
  return match ? `v${match[1]}` : null;
};

/** City and country (or region when there is no city), for narrow places. */
export const shortLocation = (place: { city: string; region: string; country: string }): string =>
  [place.city || place.region, place.country].filter(Boolean).join(", ");
