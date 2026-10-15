export type ViewId = "overview" | "upstreams" | "activity" | "diagnostics" | "settings";
export type ActivityTab = "connections" | "logs";

export const navItems: { id: ViewId; label: string; icon: string }[] = [
  { id: "overview", label: "Overview", icon: "overview" },
  { id: "upstreams", label: "Upstreams", icon: "upstream" },
  { id: "activity", label: "Activity", icon: "activity" },
  { id: "diagnostics", label: "Diagnostics", icon: "flask" },
  { id: "settings", label: "Settings", icon: "sliders" },
];

export interface NavigationTarget {
  view: ViewId;
  activityTab?: ActivityTab;
}

const destinations: Record<string, NavigationTarget> = {
  overview: { view: "overview" },
  home: { view: "overview" },
  upstreams: { view: "upstreams" },
  proxies: { view: "upstreams" },
  profiles: { view: "upstreams" },
  activity: { view: "activity" },
  connections: { view: "activity", activityTab: "connections" },
  logs: { view: "activity", activityTab: "logs" },
  diagnostics: { view: "diagnostics" },
  test: { view: "diagnostics" },
  settings: { view: "settings" },
};

/**
 * Maps a tray menu destination to a page. The pre-v2 page ids stay accepted
 * so older native builds and pending navigations still land somewhere sensible;
 * unknown values are ignored.
 */
export const trayDestination = (destination: string | null): NavigationTarget | null =>
  destination !== null && Object.hasOwn(destinations, destination)
    ? destinations[destination]
    : null;
