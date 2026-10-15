import { useState } from "react";
import type { ActivityTab } from "../../app/navigation";
import { useI18n } from "../../i18n";
import type { ConnectionState, TrafficSnapshot } from "../../types";
import { ConnectionsPage } from "../connections/ConnectionsPage";
import { LogsPage } from "../logs/LogsPage";
import { formatBytes, formatRate } from "../traffic/traffic-model";
import "./activity.css";

interface ActivityPageProps {
  tab: ActivityTab;
  onTabChange: (tab: ActivityTab) => void;
  canObserveTraffic: boolean;
  canObserveLogs: boolean;
  traffic: TrafficSnapshot | null;
  upstreamName: string | null;
}

export function ActivityPage({ tab, onTabChange, canObserveTraffic, canObserveLogs, traffic, upstreamName }: ActivityPageProps) {
  const { t, tf } = useI18n();
  const [connectionState, setConnectionState] = useState<ConnectionState>("active");
  const activeCount = canObserveTraffic && traffic ? traffic.activeConnections : null;
  return (
    <div className="page activity-page">
      <header className="page-header activity-header">
        <div>
          <h1>{t("Activity")}</h1>
          <div className="page-tabs" role="tablist" aria-label={t("Activity")}>
            <button type="button" role="tab" aria-selected={tab === "connections"} onClick={() => onTabChange("connections")}>
              {t("Connections")}{activeCount !== null && <span className="tab-count">{activeCount}</span>}
            </button>
            <button type="button" role="tab" aria-selected={tab === "logs"} onClick={() => onTabChange("logs")}>
              {t("Logs")}
            </button>
          </div>
        </div>
        {canObserveTraffic && traffic && (
          <div className="activity-stats">
            <span>↓ {formatRate(traffic.downloadBps)}</span>
            <span>↑ {formatRate(traffic.uploadBps)}</span>
            <span>{tf("This session ↓ {down} · ↑ {up}", { down: formatBytes(traffic.downloadTotal), up: formatBytes(traffic.uploadTotal) })}</span>
          </div>
        )}
      </header>
      {tab === "connections" ? (
        <ConnectionsPage
          running={canObserveTraffic}
          state={connectionState}
          onStateChange={setConnectionState}
          upstreamName={upstreamName}
        />
      ) : (
        <LogsPage running={canObserveLogs} />
      )}
    </div>
  );
}
