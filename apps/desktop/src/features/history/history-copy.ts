import type { Language } from "../../i18n";
import type { TunnelEvent, WatchdogReason } from "../../types";
import { blockDurationBefore, durationParts } from "./history-model";

type Translate = (text: string) => string;
type TranslateFormat = (template: string, values: Record<string, string | number>) => string;

export type EventTone = "accent" | "amber" | "danger" | "neutral" | "faint";

/** Short cause for automatic stops, faults and blocks (English catalog keys). */
export const eventReasonLabel = (reason: WatchdogReason | undefined): string | null => {
  switch (reason) {
    case "upstream_unavailable":
      return "Upstream unreachable";
    case "engine_exited":
      return "Engine exited unexpectedly";
    case "adapter_missing":
      return "TUN adapter disappeared";
    case "controller_unavailable":
      return "Engine stopped responding";
    case "runtime_identity_mismatch":
      return "Running tunnel could not be verified";
    case "lease_expired":
      return "TunBridge stopped responding";
    case "connection_storm":
      return "Connection storm";
    default:
      return null;
  }
};

/** Title, optional detail key and tone for one event (English catalog keys). */
export const eventTitle = (event: TunnelEvent): { title: string; tone: EventTone } => {
  switch (event.kind) {
    case "app_started":
      return { title: "TunBridge started", tone: "faint" };
    case "started":
      return event.actor === "user"
        ? { title: "You turned on System TUN", tone: "neutral" }
        : { title: "TunBridge found the tunnel already running", tone: "neutral" };
    case "stopped":
      return event.actor === "user"
        ? { title: "You turned off System TUN", tone: "neutral" }
        : event.actor === "service"
          ? { title: "The tunnel was stopped automatically", tone: "danger" }
          : { title: "The tunnel was stopped outside this App", tone: "neutral" };
    case "blocked":
      return { title: event.reason === "upstream_unavailable" ? "Upstream unreachable; traffic blocked" : "Tunnel fault; traffic blocked", tone: "amber" };
    case "resumed":
      return { title: event.reason === "upstream_unavailable" || !event.reason ? "Upstream back; traffic resumed" : "Tunnel recovered; traffic resumed", tone: "accent" };
    case "faulted":
      return { title: "The tunnel is held after a fault", tone: "danger" };
    case "recovered":
      return { title: "You restored the previous network", tone: "neutral" };
    case "start_failed":
      return { title: "Turning on System TUN failed", tone: "danger" };
  }
};

export const formatDuration = (milliseconds: number, tf: TranslateFormat): string => {
  const { hours, minutes, seconds } = durationParts(milliseconds);
  if (hours > 0) return tf("{h} h {m} min", { h: hours, m: minutes });
  if (minutes > 0) return tf("{m} min {s} s", { m: minutes, s: seconds });
  return tf("{s} s", { s: seconds });
};

/** HH:mm today, otherwise with the date. */
export const formatEventTime = (atUnixMs: number, language: Language, now = Date.now()): string => {
  const sameDay = new Date(atUnixMs).toDateString() === new Date(now).toDateString();
  return new Intl.DateTimeFormat(language, sameDay
    ? { hour: "2-digit", minute: "2-digit", hour12: false }
    : { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false }).format(atUnixMs);
};

/** The secondary line of one event, already translated. */
export const eventDetail = (
  events: TunnelEvent[],
  index: number,
  t: Translate,
  tf: TranslateFormat,
  profileName: (profileId: string) => string | undefined,
): string | null => {
  const event = events[index];
  switch (event.kind) {
    case "app_started":
      return t("Changes while it was not running were not recorded");
    case "started":
    case "start_failed": {
      const name = event.profileId ? profileName(event.profileId) : undefined;
      return name ? tf("Upstream: {name}", { name }) : null;
    }
    case "stopped": {
      if (event.actor === "user") return t("The previous network was restored");
      const reason = eventReasonLabel(event.reason);
      return reason ? t(reason) : null;
    }
    case "blocked":
    case "faulted": {
      const reason = event.kind === "faulted" || event.reason !== "upstream_unavailable" ? eventReasonLabel(event.reason) : null;
      return reason ? t(reason) : null;
    }
    case "resumed": {
      const blocked = blockDurationBefore(events, index);
      return blocked === null ? null : tf("Blocked for {duration}", { duration: formatDuration(blocked, tf) });
    }
    case "recovered":
      return null;
  }
};
