import { useEffect, useMemo, useState } from "react";
import { useI18n } from "../../i18n";
import type { ConnectionPage, ConnectionState, ConnectionView, TrafficError } from "../../types";
import { Icon } from "../../ui/Icon";
import { Select } from "../../ui/Select";
import {
  connectionRoute,
  routeBadge,
  routeFilters,
  destinationAddress,
  destinationPort,
  durationLabel,
  matchesRouteFilter,
  routeCounts,
  type RouteFilter,
} from "../activity/route-model";
import { maskIpAddress } from "../home/home-model";
import { newObservationGate, observationFailed, observationSucceeded } from "../traffic/observation-gate";
import { formatBytes, formatRate } from "../traffic/traffic-model";
import {
  closeAllConnections,
  closeConnection,
  CONNECTION_PAGE_SIZE,
  loadConnectionsPage,
  normalizeConnectionError,
} from "./connections-client";
import { connectionRuleLabel, filterAndSortConnections, type ConnectionSort } from "./connections-model";

interface ConnectionsPageProps {
  running: boolean;
  state: ConnectionState;
  onStateChange: (state: ConnectionState) => void;
  upstreamName: string | null;
}

const timeLabel = (value: string | number): string => {
  const timestamp = typeof value === "number" ? value : Date.parse(value);
  return Number.isFinite(timestamp)
    ? new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(timestamp)
    : "—";
};

const elapsed = (connection: ConnectionView, now: number): string => {
  const started = Date.parse(connection.startedAt);
  if (!Number.isFinite(started)) return "—";
  return durationLabel((connection.closedAtUnixMs ?? now) - started);
};

export function ConnectionsPage({ running, state, onStateChange, upstreamName }: ConnectionsPageProps) {
  const { t, tf } = useI18n();
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState<ConnectionPage | null>(null);
  const [error, setError] = useState<TrafficError | null>(null);
  const [loading, setLoading] = useState(false);
  const [paused, setPaused] = useState(false);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<RouteFilter>("all");
  const [sort, setSort] = useState<ConnectionSort>("speed");
  const [refreshToken, setRefreshToken] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(true);
  const [closing, setClosing] = useState<string | null>(null);
  const [armedConnectionId, setArmedConnectionId] = useState<string | null>(null);
  const [closeAllArmed, setCloseAllArmed] = useState(false);
  const now = page ? Date.now() : 0;

  useEffect(() => {
    setOffset(0);
    setPage(null);
    setSelectedId(null);
  }, [state]);

  useEffect(() => {
    if (!running) {
      setPage(null);
      setError(null);
      setLoading(false);
      return;
    }
    if (paused) return;
    let active = true;
    let inFlight = false;
    const gate = newObservationGate(Date.now(), page !== null);
    const refresh = async () => {
      if (!active || inFlight || document.visibilityState !== "visible") return;
      inFlight = true;
      if (!page) setLoading(true);
      try {
        const next = await loadConnectionsPage(state, offset);
        if (!active) return;
        observationSucceeded(gate);
        setPage(next);
        setError(null);
      } catch (loadError) {
        if (active) setError(observationFailed(gate, normalizeConnectionError(loadError), Date.now()));
      } finally {
        inFlight = false;
        if (active) setLoading(false);
      }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 1_500);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [running, state, offset, refreshToken, paused]);

  const closeOne = async (connectionId: string) => {
    if (closing) return;
    if (armedConnectionId !== connectionId) {
      setArmedConnectionId(connectionId);
      setCloseAllArmed(false);
      return;
    }
    setClosing(connectionId);
    setError(null);
    try {
      await closeConnection(connectionId);
      setArmedConnectionId(null);
      setRefreshToken((value) => value + 1);
    } catch (closeError) {
      setError(normalizeConnectionError(closeError));
    } finally {
      setClosing(null);
    }
  };

  const closeAll = async () => {
    if (closing) return;
    if (!closeAllArmed) {
      setCloseAllArmed(true);
      setArmedConnectionId(null);
      return;
    }
    setClosing("all");
    setError(null);
    try {
      await closeAllConnections();
      setCloseAllArmed(false);
      setOffset(0);
      setRefreshToken((value) => value + 1);
    } catch (closeError) {
      setError(normalizeConnectionError(closeError));
    } finally {
      setClosing(null);
    }
  };

  const items = page?.items ?? [];
  const rows = useMemo(
    () => filterAndSortConnections(items, query, sort).filter((item) => matchesRouteFilter(item, filter)),
    [page, query, sort, filter],
  );
  const total = page?.total ?? 0;
  // The service pages connections 25 at a time; counts are only exact when
  // every connection is on this page.
  const counts = page && total <= CONNECTION_PAGE_SIZE ? routeCounts(items) : null;
  const pageNumber = Math.floor(offset / CONNECTION_PAGE_SIZE) + 1;
  const pageCount = Math.max(1, Math.ceil(total / CONNECTION_PAGE_SIZE));
  const selected = items.find((item) => item.id === selectedId) ?? null;
  const sortButton = (key: ConnectionSort, label: string) => (
    <button type="button" className={sort === key ? "sort-button active" : "sort-button"} aria-pressed={sort === key} onClick={() => setSort(key)}>{label}</button>
  );

  return (
    <div className="connections">
      <div className="connections-toolbar">
        <label className="search-field">
          <Icon name="search" size={15} />
          <span className="sr-only">{t("Search connections")}</span>
          <input type="search" maxLength={128} placeholder={t("Search host, process, rule…")} value={query} onChange={(event) => setQuery(event.target.value)} />
        </label>
        <div className="chip-group" role="radiogroup" aria-label={t("Route")}>
          {routeFilters.map((item) => (
            <button key={item.id} type="button" role="radio" aria-checked={filter === item.id} className={filter === item.id ? "chip active" : "chip"} onClick={() => setFilter(item.id)}>
              {t(item.label)}{counts && <span>{counts[item.id]}</span>}
            </button>
          ))}
        </div>
        <Select<ConnectionState> compact ariaLabel={t("Connection state")} value={state} onChange={onStateChange} options={[
          { value: "active", label: t("Active") },
          { value: "closed", label: t("Closed") },
        ]} />
        <div className="toolbar-end">
          <button type="button" className="btn" aria-pressed={paused} disabled={!running} onClick={() => setPaused((value) => !value)}>{t(paused ? "Resume refresh" : "Pause refresh")}</button>
          {state === "active" && (
            <button type="button" className="btn btn-danger" disabled={!running || total === 0 || closing !== null} onClick={() => void closeAll()}>
              {closing === "all" ? t("Closing…") : closeAllArmed ? tf("Confirm closing {count}", { count: total }) : t("Close all connections…")}
            </button>
          )}
        </div>
      </div>

      <div className={selected ? "connections-body with-detail" : "connections-body"}>
        <section className="panel connections-table-panel">
          {!running && (
            <div className="empty-panel">
              <strong>{t("Start the tunnel to see connections")}</strong>
              <span>{t("Only redacted metadata from the TunBridge-owned engine is shown.")}</span>
            </div>
          )}
          {running && loading && !page && <div className="empty-panel"><strong>{t("Loading connections…")}</strong></div>}
          {running && error && !page && (
            <div className="empty-panel" role="status">
              <strong>{t(error.safeMessage)}</strong>
              <span>{error.retryable ? t("TunBridge will retry automatically.") : error.code}</span>
            </div>
          )}
          {running && page && (
            <>
              <div className="table-scroll">
                <table className="data-table connections-table">
                  <thead>
                    <tr>
                      <th>{sortButton("host", t("Host / process"))}</th>
                      <th>{t("Route")}</th>
                      <th>{t("Rule")}</th>
                      <th className="numeric">{sortButton("download", "↓ / ↑")}</th>
                      <th className="numeric">{sortButton("started", t("Duration"))}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((connection) => {
                      const route = connectionRoute(connection.chains);
                      return (
                        <tr
                          key={connection.id}
                          className={connection.id === selectedId ? "selected" : undefined}
                          tabIndex={0}
                          aria-selected={connection.id === selectedId}
                          onClick={() => { setSelectedId(connection.id); setRevealed(true); }}
                          onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setSelectedId(connection.id); } }}
                        >
                          <td className="host-cell">
                            <strong title={connection.host}>{connection.host}</strong>
                            <span>{[connection.processName, connection.network.toUpperCase()].filter(Boolean).join(" · ")}</span>
                          </td>
                          <td><span className={`badge ${routeBadge[route].tone}`}>{t(routeBadge[route].label)}</span></td>
                          <td className="mono rule-cell" title={connectionRuleLabel(connection)}>{connectionRuleLabel(connection)}</td>
                          <td className="numeric">{formatBytes(connection.downloadTotal)} / {formatBytes(connection.uploadTotal)}</td>
                          <td className="numeric">{elapsed(connection, now)}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                {rows.length === 0 && (
                  <div className="empty-panel compact">
                    {query || filter !== "all" ? t("No connections match this filter.") : t(state === "active" ? "No active connections." : "No closed connections.")}
                  </div>
                )}
              </div>
              <footer className="panel-foot">
                <span>{tf("Page {page} of {pages} · {total} connections", { page: pageNumber, pages: pageCount, total })}{filter !== "all" && total > CONNECTION_PAGE_SIZE ? ` · ${t("filters apply to this page")}` : ""}</span>
                {error && <span className="foot-warning">{t(error.safeMessage)}</span>}
                <span className="pager">
                  <button type="button" className="btn" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - CONNECTION_PAGE_SIZE))}>{t("Previous")}</button>
                  <button type="button" className="btn" disabled={offset + CONNECTION_PAGE_SIZE >= total} onClick={() => setOffset(offset + CONNECTION_PAGE_SIZE)}>{t("Next")}</button>
                </span>
              </footer>
            </>
          )}
        </section>

        {selected && (
          <aside className="panel connection-detail" aria-label={t("Connection details")}>
            <div className="connection-detail-head">
              <div>
                <h3>{selected.host}</h3>
                <span>{[destinationPort(selected.destination) && `:${destinationPort(selected.destination)}`, selected.network.toUpperCase()].filter(Boolean).join(" · ")}</span>
              </div>
              <button type="button" className="icon-close" aria-label={t("Close details")} onClick={() => setSelectedId(null)}><Icon name="close" size={14} /></button>
            </div>
            <div className={`route-summary route-${connectionRoute(selected.chains)}`}>
              <span>{t("Route")}</span>
              <strong>{connectionRoute(selected.chains) === "upstream"
                ? tf("System TUN → {upstream} → internet", { upstream: upstreamName ?? t("upstream") })
                : connectionRoute(selected.chains) === "direct"
                  ? t("System TUN → direct")
                  : connectionRoute(selected.chains) === "rejected" ? t("Rejected by a rule") : t("Not determined")}</strong>
            </div>
            <dl className="detail-list">
              <dt>{t("Process")}</dt><dd>{selected.processName ?? t("Not reported")}</dd>
              <dt>{t("Destination IP")}</dt>
              <dd className="mono">
                {revealed ? destinationAddress(selected.destination) : maskIpAddress(destinationAddress(selected.destination))}
                {" "}<button type="button" className="btn btn-link inline" onClick={() => setRevealed((value) => !value)}>{t(revealed ? "Hide" : "Show")}</button>
              </dd>
              <dt>{t("Rule")}</dt><dd className="mono">{connectionRuleLabel(selected)} → {selected.chains.join(" / ") || "—"}</dd>
              <dt>{t("Started")}</dt><dd>{timeLabel(selected.startedAt)}</dd>
              {selected.closedAtUnixMs && <><dt>{t("Closed")}</dt><dd>{timeLabel(selected.closedAtUnixMs)}</dd></>}
              <dt>{t("Traffic")}</dt><dd>↓ {formatBytes(selected.downloadTotal)} · ↑ {formatBytes(selected.uploadTotal)}</dd>
              {state === "active" && <><dt>{t("Rate")}</dt><dd>↓ {formatRate(selected.downloadBps)} · ↑ {formatRate(selected.uploadBps)}</dd></>}
            </dl>
            <div className="connection-detail-foot">
              {state === "active" && (
                <button type="button" className="btn btn-danger full" disabled={closing !== null} onClick={() => void closeOne(selected.id)}>
                  {t(closing === selected.id ? "Closing…" : armedConnectionId === selected.id ? "Confirm close" : "Close this connection")}
                </button>
              )}
              <span>{t("Only connection metadata is shown; traffic content is never inspected.")}</span>
            </div>
          </aside>
        )}
      </div>
    </div>
  );
}
