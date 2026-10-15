import { invoke } from "../../bridge";
import type { TunnelEventPage } from "../../types";

/** The newest locally recorded tunnel events, oldest first. */
export const loadTunnelEvents = (): Promise<TunnelEventPage> =>
  invoke<TunnelEventPage>("get_tunnel_events");
