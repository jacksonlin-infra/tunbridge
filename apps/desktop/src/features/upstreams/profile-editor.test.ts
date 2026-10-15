import { describe, expect, it } from "vitest";
import type { SavedProfile } from "../../types";
import { profileEndpointLabel, profileProtocolOf } from "./profile-format";
import { editorFieldsFrom, emptyEditorFields, upstreamFromFields } from "./use-profiles";

const remote: SavedProfile = {
  profileId: "remote",
  displayName: "Office",
  hasCredential: true,
  upstream: {
    kind: "remote_server",
    endpoint: { host: "proxy.example.com", port: 443, ipPreference: "ipv4_prefer" },
    protocolConfig: { protocol: "socks5", tls: true, sni: "edge.example.com", udp: false, certificatePolicy: "strict" },
  },
};

describe("profile editor fields", () => {
  it("loads a remote profile without credentials and round-trips its upstream", () => {
    const fields = editorFieldsFrom(remote);
    expect(fields).toMatchObject({
      name: "Office",
      upstreamKind: "remote_server",
      host: "proxy.example.com",
      port: "443",
      tls: true,
      sni: "edge.example.com",
      udp: false,
      credentialMode: "keep",
      username: "",
      password: "",
    });
    expect(upstreamFromFields(fields)).toEqual(remote.upstream);
  });

  it("drops TLS-only settings when TLS is off", () => {
    const upstream = upstreamFromFields({
      ...emptyEditorFields(),
      upstreamKind: "remote_server",
      host: " 192.168.1.20 ",
      port: "1080",
      protocol: "http",
      sni: "ignored",
      certificatePolicy: "insecure",
    });
    expect(upstream).toEqual({
      kind: "remote_server",
      endpoint: { host: "192.168.1.20", port: 1080, ipPreference: "ipv4_prefer" },
      protocolConfig: { protocol: "http", tls: false, sni: null, certificatePolicy: "strict" },
    });
  });

  it("formats local and remote endpoints", () => {
    const local = { kind: "local_listener", port: 7890, protocol: "socks5" } as const;
    expect(profileEndpointLabel(local)).toBe("127.0.0.1:7890");
    expect(profileProtocolOf(local)).toBe("socks5");
    expect(profileEndpointLabel(remote.upstream)).toBe("proxy.example.com:443");
  });
});
