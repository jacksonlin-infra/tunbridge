import type { ReactNode } from "react";
import { Icon } from "../../ui/Icon";
import type { TunnelTone } from "./overview-model";

interface TunnelCardProps {
  tone: TunnelTone;
  icon: string;
  overline: string;
  title: string;
  description: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
  busy?: boolean;
}

/** The overview's main card: state header, optional body, and a footer strip. */
export function TunnelCard({ tone, icon, overline, title, description, actions, children, footer, busy }: TunnelCardProps) {
  return (
    <section className={`tunnel-card tone-${tone}`} aria-live="polite" aria-busy={busy || undefined}>
      <div className="tunnel-card-head">
        <div className="tunnel-card-title">
          <span className={busy ? "tunnel-card-icon busy" : "tunnel-card-icon"}><Icon name={icon} size={28} strokeWidth={1.7} /></span>
          <div>
            <span className="tunnel-overline">{overline}</span>
            <h2>{title}</h2>
            <div className="tunnel-description">{description}</div>
          </div>
        </div>
        {actions && <div className="tunnel-card-actions">{actions}</div>}
      </div>
      {children}
      {footer && <div className="tunnel-card-foot">{footer}</div>}
    </section>
  );
}

export type HopState = "ok" | "warn" | "fail" | "idle";

export interface Hop {
  key: string;
  label: string;
  state: HopState;
  title: ReactNode;
  detail?: ReactNode;
  mono?: boolean;
  emphasis?: boolean;
}

/** app → TUN → upstream → exit, with the failing hop and the links around it marked. */
export function RouteChain({ hops, label }: { hops: Hop[]; label: string }) {
  return (
    <div className="route-chain" aria-label={label}>
      {hops.map((hop, index) => {
        const next = hops[index + 1];
        const link = !next ? null : next.state === "fail" ? "broken" : next.state === "idle" ? "idle" : "ok";
        return (
          <div className="route-chain-segment" key={hop.key}>
            <div className={`route-hop hop-${hop.state}${hop.emphasis ? " emphasis" : ""}`}>
              <span className="route-hop-label">
                {hop.state !== "idle" && <span className="route-hop-dot" aria-hidden="true" />}
                {hop.label}
              </span>
              <strong className={hop.mono ? "mono" : undefined}>{hop.title}</strong>
              {hop.detail && <span className="route-hop-detail">{hop.detail}</span>}
            </div>
            {link && (
              <span className={`route-link link-${link}`} aria-hidden="true">
                {link === "broken" ? (
                  <svg width="22" height="10" viewBox="0 0 22 10" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"><path d="M1 5h5M16 5h5M8.5 2l5 6M13.5 2l-5 6" /></svg>
                ) : link === "idle" ? (
                  <svg width="22" height="10" viewBox="0 0 22 10" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeDasharray="3 3"><path d="M1 5h20" /></svg>
                ) : (
                  <svg width="22" height="10" viewBox="0 0 22 10" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M1 5h19M16 1l4 4-4 4" /></svg>
                )}
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}
