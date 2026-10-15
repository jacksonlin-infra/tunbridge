import { invoke } from "../../bridge";
import type {
  CloseConnectionsResult,
  ConnectionPage,
  ConnectionState,
  TrafficError,
} from "../../types";
import { normalizeTrafficError } from "../traffic/traffic-client";

export const CONNECTION_PAGE_SIZE = 25;

export const loadConnectionsPage = (
  state: ConnectionState,
  offset: number,
): Promise<ConnectionPage> =>
  invoke<ConnectionPage>("get_connections_page", {
    input: {
      state,
      offset,
      limit: CONNECTION_PAGE_SIZE,
    },
  });

export const normalizeConnectionError = (error: unknown): TrafficError =>
  normalizeTrafficError(error);

export const closeConnection = (
  connectionId: string,
): Promise<CloseConnectionsResult> =>
  invoke<CloseConnectionsResult>("close_connection", {
    input: { connectionId },
  });

export const closeAllConnections = (): Promise<CloseConnectionsResult> =>
  invoke<CloseConnectionsResult>("close_all_connections");
