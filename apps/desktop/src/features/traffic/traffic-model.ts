import type { TrafficSnapshot } from "../../types";

export const MAX_TRAFFIC_POINTS = 600;

export interface TrafficPoint {
  engineGeneration: string;
  sequence: number;
  sampledAtUnixMs: number;
  uploadBps: number;
  downloadBps: number;
}

export const appendTrafficPoint = (
  points: TrafficPoint[],
  snapshot: TrafficSnapshot,
  limit = MAX_TRAFFIC_POINTS,
): TrafficPoint[] => {
  const previous = points.at(-1);
  const point: TrafficPoint = {
    engineGeneration: snapshot.engineGeneration,
    sequence: snapshot.sequence,
    sampledAtUnixMs: snapshot.sampledAtUnixMs,
    uploadBps: snapshot.uploadBps,
    downloadBps: snapshot.downloadBps,
  };
  if (
    !previous ||
    previous.engineGeneration !== point.engineGeneration ||
    point.sequence <= previous.sequence
  ) {
    return [point];
  }
  const next = [...points, point];
  return next.length > limit ? next.slice(next.length - limit) : next;
};

export const formatBytes = (bytes: number): string => {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** exponent;
  const digits = value >= 100 || exponent === 0 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(digits)} ${units[exponent]}`;
};

export const formatRate = (bytesPerSecond: number): string =>
  `${formatBytes(bytesPerSecond)}/s`;

export const formatClock = (timestamp: number): string =>
  new Date(timestamp).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

/** A rate split into its number and unit, for large numeric displays. */
export const splitRate = (bytesPerSecond: number): { value: string; unit: string } => {
  const [value, unit] = formatBytes(bytesPerSecond).split(" ");
  return { value, unit: `${unit}/s` };
};
