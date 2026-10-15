import { useI18n } from "../../i18n";
import type { SavedProfile, TunnelEvent } from "../../types";
import { formatBytes } from "../traffic/traffic-model";
import { EventList } from "./EventList";
import { formatDuration, formatEventTime } from "./history-copy";
import type { SessionSummary } from "./history-model";

interface RecentEventsCardProps {
  events: TunnelEvent[];
  profiles: SavedProfile[];
  now: number;
}

export function RecentEventsCard({ events, profiles, now }: RecentEventsCardProps) {
  const { t } = useI18n();
  return (
    <section className="panel history-card">
      <div className="panel-head"><h3>{t("Recent events")}</h3></div>
      <div className="panel-body">
        <EventList events={events} profiles={profiles} limit={5} now={now} />
      </div>
      <div className="panel-foot"><span className="history-note">{t("Recorded by this App; changes while it is not running are not recorded.")}</span></div>
    </section>
  );
}

interface LastSessionCardProps {
  summary: SessionSummary | null;
  events: TunnelEvent[];
  profiles: SavedProfile[];
  now: number;
}

export function LastSessionCard({ summary, events, profiles, now }: LastSessionCardProps) {
  const { t, tf, language } = useI18n();
  const profileName = summary?.profileId
    ? profiles.find((profile) => profile.profileId === summary.profileId)?.displayName
    : undefined;
  const range = summary
    ? [
        summary.startedAt === null ? null : `${summary.exactStart ? "" : "≥ "}${formatEventTime(summary.startedAt, language, now)} – ${formatEventTime(summary.endedAt, language, now)}`,
        profileName,
      ].filter(Boolean).join(" · ")
    : "";
  return (
    <section className="panel history-card">
      <div className="panel-head">
        <h3>{t(summary ? "Last session" : "Recent events")}</h3>
        {range && <span className="panel-meta">{range}</span>}
      </div>
      <div className="panel-body">
        {summary && (
          <div className="session-stats">
            {summary.startedAt !== null && (
              <div className="session-stat">
                <span>{t("Duration")}</span>
                <strong>{summary.exactStart ? "" : "≥ "}{formatDuration(summary.endedAt - summary.startedAt, tf)}</strong>
              </div>
            )}
            {summary.downloadTotal !== undefined && summary.uploadTotal !== undefined && (
              <div className="session-stat">
                <span>{t("Download / upload")}</span>
                <strong className="session-traffic">
                  <span>↓ {formatBytes(summary.downloadTotal)}</span>
                  <span>↑ {formatBytes(summary.uploadTotal)}</span>
                </strong>
              </div>
            )}
            <div className="session-stat">
              <span>{t("Upstream outages")}</span>
              <strong>{summary.outages === 0
                ? tf("{count} times", { count: 0 })
                : `${tf("{count} times", { count: summary.outages })} · ${formatDuration(summary.blockedMs, tf)}`}</strong>
            </div>
          </div>
        )}
        {summary && <h4 className="session-subhead">{t("Recent events")}</h4>}
        <EventList events={events} profiles={profiles} limit={4} now={now} />
      </div>
      <div className="panel-foot"><span className="history-note">{t("Recorded by this App; changes while it is not running are not recorded.")}</span></div>
    </section>
  );
}
