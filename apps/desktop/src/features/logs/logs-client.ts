import { invoke } from "../../bridge";
import type { MihomoLogPage, TrafficError } from "../../types";
import { normalizeTrafficError } from "../traffic/traffic-client";

export const MIHOMO_LOG_PAGE_SIZE = 25;

export const loadMihomoLogsPage = (afterSequence: number): Promise<MihomoLogPage> =>
  invoke<MihomoLogPage>("get_mihomo_logs_page", {
    input: { afterSequence, limit: MIHOMO_LOG_PAGE_SIZE },
  });

export const normalizeMihomoLogError = (error: unknown): TrafficError =>
  normalizeTrafficError(error);
