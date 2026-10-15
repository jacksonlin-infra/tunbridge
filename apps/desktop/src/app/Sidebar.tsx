import type { TunnelAppearance } from "../features/overview/overview-model";
import { appearanceTone } from "../features/overview/overview-model";
import { reasonLabel, tunnelSummary } from "../features/overview/tunnel-copy";
import { durationLabel } from "../features/activity/route-model";
import { shortLocation } from "../features/home/home-model";
import { formatBytes, formatRate } from "../features/traffic/traffic-model";
import { useI18n } from "../i18n";
import type { IpInformation, TrafficSnapshot } from "../types";
import appIcon from "../ui/app-icon.svg?no-inline";
import { Icon } from "../ui/Icon";
import { navItems, type ViewId } from "./navigation";

interface SidebarProps {
  activeView: ViewId;
  onNavigate: (view: ViewId) => void;
  appearance: TunnelAppearance;
  /** Only counts with a real source; a missing key hides the badge. */
  counts: Partial<Record<ViewId, number>>;
  updatePending: boolean;
  traffic: TrafficSnapshot | null;
  versionLine: string | null;
  session: { elapsed: number; exact: boolean } | null;
  exitIp: IpInformation | null;
}

export function Sidebar({
  activeView,
  onNavigate,
  appearance,
  counts,
  updatePending,
  traffic,
  versionLine,
  session,
  exitIp,
}: SidebarProps) {
  const { t } = useI18n();
  // Clock form (m:ss or h:mm:ss) so it fits beside the title; "≥" marks a lower bound.
  const durationText = session ? `${session.exact ? "" : "≥ "}${durationLabel(session.elapsed)}` : null;
  const tunnelOn = appearance.kind === "running" || appearance.kind === "blocked";
  const summary = tunnelSummary(appearance);
  const tone = appearanceTone(appearance);
  return (
    <aside className="sidebar">
      <div className="brand">
        <img src={appIcon} width={34} height={34} alt="" />
        <div>
          <strong>TunBridge</strong>
          {versionLine && <span>{versionLine}</span>}
        </div>
      </div>

      <nav aria-label={t("Primary navigation")}>
        {navItems.map((item) => (
          <button
            type="button"
            key={item.id}
            className={activeView === item.id ? "nav-item active" : "nav-item"}
            aria-current={activeView === item.id ? "page" : undefined}
            onClick={() => onNavigate(item.id)}
          >
            <Icon name={item.icon} size={18} strokeWidth={1.7} />
            <span className="nav-label">{t(item.label)}</span>
            {counts[item.id] !== undefined && <span className="nav-count">{counts[item.id]}</span>}
            {item.id === "settings" && updatePending && (
              <span className="nav-update-indicator">
                <span className="sr-only">{t("Update available")}</span>
              </span>
            )}
          </button>
        ))}
      </nav>

      <div className={`sidebar-tunnel tone-${tone}`} role="status">
        <div className="sidebar-tunnel-head">
          <strong><span className={`state-dot tone-${tone}`} aria-hidden="true" />{t(summary.title)}</strong>
          {tunnelOn && durationText && (
            <span
              className="sidebar-duration"
              aria-label={`${t("Connected for")} ${durationText}`}
              title={session?.exact ? t("Connected for") : t("Counted from when TunBridge first saw the tunnel running")}
            >{durationText}</span>
          )}
        </div>
        {appearance.kind === "running" && traffic ? (
          <span className="sidebar-rates">
            <span>↓ {formatRate(traffic.downloadBps)}</span>
            <span>↑ {formatRate(traffic.uploadBps)}</span>
          </span>
        ) : (
          <span>{appearance.kind === "blocked" ? t(reasonLabel(appearance.reason)) : t(summary.detail)}</span>
        )}
        {tunnelOn && (traffic || (appearance.kind === "running" && exitIp)) && (
          <dl className="sidebar-facts">
            {traffic && <><dt>{t("Session traffic")}</dt><dd>↓ {formatBytes(traffic.downloadTotal)} · ↑ {formatBytes(traffic.uploadTotal)}</dd></>}
            {appearance.kind === "running" && exitIp && <>
              <dt>{t("Exit IP")}</dt>
              <dd className="sidebar-exit">
                <span className="mono">{exitIp.ip}</span>
                {shortLocation(exitIp) && <span>{shortLocation(exitIp)}</span>}
              </dd>
            </>}
          </dl>
        )}
      </div>
      <div className="sidebar-policy">
        <Icon name="lock" size={13} />
        <span>{t("Blocks on outage, never direct")}</span>
      </div>
    </aside>
  );
}
