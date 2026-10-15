import type { ConnectionView } from "../../types";

/**
 * How the engine routed one connection, read from its proxy chain. Every
 * platform names the upstream proxy `upstream`; direct rules use `DIRECT`
 * (Windows, Linux) or `direct-default` (macOS).
 */
export type ConnectionRoute = "upstream" | "direct" | "rejected" | "unknown";

export type RouteFilter = "all" | "upstream" | "direct";

/** Badge copy (English catalog keys) and tone for each route. */
export const routeBadge: Record<ConnectionRoute, { label: string; tone: string }> = {
  upstream: { label: "Via upstream", tone: "accent" },
  direct: { label: "Direct", tone: "direct" },
  rejected: { label: "Rejected", tone: "danger" },
  unknown: { label: "Unknown", tone: "" },
};

export const routeFilters: { id: RouteFilter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "upstream", label: "Via upstream" },
  { id: "direct", label: "Direct" },
];

export const UPSTREAM_PROXY_NAME = "upstream";

export const connectionRoute = (chains: string[]): ConnectionRoute => {
  const names = chains.map((name) => name.trim().toLowerCase());
  if (names.includes(UPSTREAM_PROXY_NAME)) return "upstream";
  if (names.some((name) => name === "direct" || name === "direct-default")) return "direct";
  if (names.some((name) => name === "reject" || name === "reject-drop")) return "rejected";
  return "unknown";
};

export const matchesRouteFilter = (connection: ConnectionView, filter: RouteFilter): boolean =>
  filter === "all" || connectionRoute(connection.chains) === filter;

export const routeCounts = (connections: ConnectionView[]): Record<RouteFilter, number> => {
  const counts = { all: connections.length, upstream: 0, direct: 0 };
  for (const connection of connections) {
    const route = connectionRoute(connection.chains);
    if (route === "upstream" || route === "direct") counts[route] += 1;
  }
  return counts;
};

/** Port and transport for the detail header, e.g. ":443 · TCP". */
export const destinationPort = (destination: string): string | null => {
  const match = destination.match(/:(\d{1,5})$/);
  return match ? match[1] : null;
};

/** The destination address without its port, for masking. */
export const destinationAddress = (destination: string): string =>
  destination.replace(/^\[(.*)\]:\d{1,5}$/, "$1").replace(/^([^:]+):\d{1,5}$/, "$1");

export const durationLabel = (milliseconds: number): string => {
  const seconds = Math.max(0, Math.floor(milliseconds / 1000));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = String(seconds % 60).padStart(2, "0");
  return hours > 0 ? `${hours}:${String(minutes).padStart(2, "0")}:${rest}` : `${minutes}:${rest}`;
};
