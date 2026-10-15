import { useI18n } from "../../i18n";
import type { TrafficError, TrafficSnapshot } from "../../types";
import { formatBytes, splitRate, type TrafficPoint } from "../traffic/traffic-model";

const WIDTH = 600;
const HEIGHT = 120;
const WINDOW = 60;

const pathFor = (points: TrafficPoint[], select: (point: TrafficPoint) => number, maximum: number) =>
  points
    .map((point, index) => {
      const x = (index / Math.max(points.length - 1, 1)) * WIDTH;
      const y = HEIGHT - 6 - (select(point) / maximum) * (HEIGHT - 16);
      return `${index === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");

interface LiveTrafficCardProps {
  snapshot: TrafficSnapshot | null;
  history: TrafficPoint[];
  error: TrafficError | null;
  onOpenActivity: () => void;
}

export function LiveTrafficCard({ snapshot, history, error, onOpenActivity }: LiveTrafficCardProps) {
  const { t, tf } = useI18n();
  const recent = history.slice(-WINDOW);
  const maximum = Math.max(1, ...recent.flatMap((point) => [point.downloadBps, point.uploadBps]));
  const download = splitRate(snapshot?.downloadBps ?? 0);
  const upload = splitRate(snapshot?.uploadBps ?? 0);
  const downloadPath = pathFor(recent, (point) => point.downloadBps, maximum);
  return (
    <section className="panel live-traffic">
      <div className="panel-head">
        <h3>{t("Live traffic")}</h3>
        <span className="panel-meta">{error ? t("Waiting for new data") : t("Last 60 seconds")}</span>
      </div>
      <div className="live-traffic-figures">
        <div>
          <span><span className="rate-arrow download">↓</span> {t("Download")}</span>
          <strong>{download.value} <small>{download.unit}</small></strong>
        </div>
        <div>
          <span><span className="rate-arrow upload">↑</span> {t("Upload")}</span>
          <strong>{upload.value} <small>{upload.unit}</small></strong>
        </div>
      </div>
      <svg className="live-traffic-chart" viewBox={`0 0 ${WIDTH} ${HEIGHT}`} preserveAspectRatio="none" role="img" aria-label={t("Download and upload speed over the last 60 seconds")}>
        <defs>
          <linearGradient id="overview-download-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" className="fill-start" />
            <stop offset="1" className="fill-end" />
          </linearGradient>
        </defs>
        <line className="grid-line" x1="0" x2={WIDTH} y1={HEIGHT * 0.35} y2={HEIGHT * 0.35} />
        <line className="grid-line" x1="0" x2={WIDTH} y1={HEIGHT * 0.7} y2={HEIGHT * 0.7} />
        {recent.length > 1 && <>
          <path d={`${downloadPath} L${WIDTH},${HEIGHT} L0,${HEIGHT} Z`} fill="url(#overview-download-fill)" />
          <path className="line-download" d={downloadPath} />
          <path className="line-upload" d={pathFor(recent, (point) => point.uploadBps, maximum)} />
        </>}
      </svg>
      <div className="panel-foot">
        <span>{snapshot ? tf("This session ↓ {down} · ↑ {up}", { down: formatBytes(snapshot.downloadTotal), up: formatBytes(snapshot.uploadTotal) }) : t("Waiting for the first sample")}</span>
        <button type="button" className="btn btn-link" onClick={onOpenActivity}>
          {snapshot ? tf("{count} active connections →", { count: snapshot.activeConnections }) : t("Open activity →")}
        </button>
      </div>
    </section>
  );
}
