import { useEffect, useMemo, useRef, useState } from "react";
import { useI18n } from "../../i18n";
import { Icon } from "../../ui/Icon";
import { Select } from "../../ui/Select";
import type { MihomoLogLevel, TrafficError } from "../../types";
import { newObservationGate, observationFailed, observationSucceeded } from "../traffic/observation-gate";
import { loadMihomoLogsPage, normalizeMihomoLogError } from "./logs-client";
import { emptyLogBuffer, filterLogs, mergeLogPage } from "./logs-model";

interface LogsPageProps {
  running: boolean;
}

const levelOptions: Array<MihomoLogLevel | "all"> = [
  "all",
  "debug",
  "info",
  "warning",
  "error",
];

const levelLabel = (level: MihomoLogLevel | "all"): string => ({
  all: "All",
  debug: "Debug",
  info: "Info",
  warning: "Warning",
  error: "Error",
})[level];

const timeLabel = (timestamp: number): string => new Intl.DateTimeFormat(undefined, {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  fractionalSecondDigits: 3,
}).format(timestamp);

export function LogsPage({ running }: LogsPageProps) {
  const { t } = useI18n();
  const [buffer, setBuffer] = useState(emptyLogBuffer);
  const [paused, setPaused] = useState(false);
  const [level, setLevel] = useState<MihomoLogLevel | "all">("all");
  const [query, setQuery] = useState("");
  const [order, setOrder] = useState<"asc" | "desc">("asc");
  const [autoScroll, setAutoScroll] = useState(true);
  const [error, setError] = useState<TrafficError | null>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const cursorRef = useRef(0);

  useEffect(() => {
    cursorRef.current = buffer.cursor;
  }, [buffer.cursor]);

  useEffect(() => {
    if (!running) {
      setBuffer(emptyLogBuffer());
      setError(null);
      setPaused(false);
      return;
    }
    if (paused) return;
    let active = true;
    let inFlight = false;
    const gate = newObservationGate(Date.now(), cursorRef.current > 0);
    const refresh = async () => {
      if (!active || inFlight || document.visibilityState !== "visible") return;
      inFlight = true;
      try {
        const page = await loadMihomoLogsPage(cursorRef.current);
        if (!active) return;
        observationSucceeded(gate);
        setBuffer((current) => mergeLogPage(current, page));
        setError(null);
      } catch (loadError) {
        if (active) setError(observationFailed(gate, normalizeMihomoLogError(loadError), Date.now()));
      } finally {
        inFlight = false;
      }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 500);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [running, paused]);

  const rows = useMemo(
    () => filterLogs(buffer.items, level, query, order),
    [buffer.items, level, query, order],
  );

  useEffect(() => {
    if (!autoScroll || paused || order !== "asc") return;
    const list = listRef.current;
    if (list) list.scrollTop = list.scrollHeight;
  }, [rows.length, autoScroll, paused, order]);

  const clearVisible = () => {
    setBuffer((current) => ({ ...current, items: [] }));
  };

  if (!running) {
    return (
      <section className="panel empty-panel">
        <strong>{t("Mihomo logs are unavailable while TunBridge is stopped.")}</strong>
        <span>{t("Start a profile to begin the bounded in-memory log session.")}</span>
      </section>
    );
  }

  return (
    <div className="logs">
      <div className="connections-toolbar">
        <label className="search-field">
          <Icon name="search" size={15} />
          <span className="sr-only">{t("Search logs")}</span>
          <input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("Search logs")} maxLength={128} />
        </label>
        <Select<MihomoLogLevel | "all"> compact ariaLabel={t("Log level")} value={level} onChange={setLevel} options={levelOptions.map((option) => ({ value: option, label: t(levelLabel(option)) }))} />
        <Select<"asc" | "desc"> compact ariaLabel={t("Log order")} value={order} onChange={setOrder} options={[
          { value: "asc", label: t("Oldest first") },
          { value: "desc", label: t("Newest first") },
        ]} />
        <div className="toolbar-end">
          <button type="button" className="btn" onClick={() => setPaused((value) => !value)} aria-pressed={paused}>
            {t(paused ? "Resume" : "Pause")}
          </button>
          <button type="button" className="btn" onClick={() => setAutoScroll((value) => !value)} aria-pressed={autoScroll}>
            {t("Auto-scroll")}
          </button>
          <button type="button" className="btn" onClick={clearVisible}>{t("Clear view")}</button>
        </div>
      </div>

      <section className="panel logs-panel">
        <div className="logs-meta">
          <span>{buffer.items.length} / 1000</span>
          {paused && <strong>{t("Display paused; collection continues in the service.")}</strong>}
          {buffer.dropped && <strong className="logs-warning">{t("Older entries were evicted from the bounded service buffer.")}</strong>}
          {error && <strong className="logs-warning" role="status">{t(error.safeMessage)} · {error.code}</strong>}
        </div>
        <div className="logs-list" ref={listRef} role="log" aria-live={paused ? "off" : "polite"}>
          {rows.length === 0 ? (
            <div className="empty-panel compact">{t("No matching log entries.")}</div>
          ) : rows.map((entry) => (
            <div className={`log-row level-${entry.level}`} key={`${buffer.engineGeneration}-${entry.sequence}`}>
              <time>{timeLabel(entry.observedAtUnixMs)}</time>
              <span className="log-level">{entry.level.toUpperCase()}</span>
              <code>{entry.message}{entry.truncated ? "…" : ""}</code>
            </div>
          ))}
        </div>
        <p className="panel-foot">{t("Logs may contain domains, IP addresses, and routing rules. They remain in memory for the current engine session and are not written to disk or uploaded.")}</p>
      </section>
    </div>
  );
}
