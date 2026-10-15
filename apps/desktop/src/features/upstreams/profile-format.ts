import type { ProfileUpstream, ProxyProtocol } from "../../types";

export const profileProtocolOf = (upstream: ProfileUpstream): ProxyProtocol =>
  upstream.kind === "local_listener" ? upstream.protocol : upstream.protocolConfig.protocol;

export const profileEndpointLabel = (upstream: ProfileUpstream): string =>
  upstream.kind === "local_listener"
    ? `127.0.0.1:${upstream.port}`
    : `${upstream.endpoint.host}:${upstream.endpoint.port}`;
