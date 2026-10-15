import { useI18n } from "../../i18n";
import type { SavedProfile, TunnelEvent } from "../../types";
import { eventDetail, eventTitle, formatEventTime } from "./history-copy";
import "./history.css";

interface EventListProps {
  events: TunnelEvent[];
  profiles: SavedProfile[];
  limit: number;
  now: number;
}

/** Newest first. The events are local records; see the card footnote. */
export function EventList({ events, profiles, limit, now }: EventListProps) {
  const { t, tf, language } = useI18n();
  const profileName = (profileId: string) => profiles.find((profile) => profile.profileId === profileId)?.displayName;
  const indexes = events.map((_, index) => index).reverse().slice(0, limit);
  if (indexes.length === 0) return <p className="event-empty">{t("No events recorded yet.")}</p>;
  return (
    <ol className="event-list">
      {indexes.map((index) => {
        const event = events[index];
        const { title, tone } = eventTitle(event);
        const detail = eventDetail(events, index, t, tf, profileName);
        return (
          <li key={`${event.atUnixMs}-${index}`}>
            <time dateTime={new Date(event.atUnixMs).toISOString()}>{formatEventTime(event.atUnixMs, language, now)}</time>
            <span className={`event-dot tone-${tone}`} aria-hidden="true" />
            <span className="event-text"><strong>{t(title)}</strong>{detail && <span className="muted"> · {detail}</span>}</span>
          </li>
        );
      })}
    </ol>
  );
}
