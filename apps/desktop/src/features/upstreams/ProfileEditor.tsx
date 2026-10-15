import { useI18n } from "../../i18n";
import { normalizeProxyError } from "../../local-proxy";
import type { ProxyProtocol } from "../../types";
import { Icon } from "../../ui/Icon";
import { Select } from "../../ui/Select";
import { testErrorLabel } from "./availability-copy";
import type { CandidateTest } from "./use-discovery";
import type { CredentialMode, ProfilesApi } from "./use-profiles";

interface ProfileEditorProps {
  profilesApi: ProfilesApi;
  credentialStore: string;
  /** The credential-free test of the listener this new profile came from. */
  candidateTest: CandidateTest | null;
}

export function ProfileEditor({ profilesApi, credentialStore, candidateTest }: ProfileEditorProps) {
  const { t, tf } = useI18n();
  const {
    editingProfile,
    editingLocked,
    fields,
    updateFields,
    profileBusy,
    testsBusy,
    profileError,
    profileTestResult,
    saveProfile,
    closeEditor,
  } = profilesApi;
  const incomplete = !fields.name.trim()
    || !fields.port.trim()
    || (fields.upstreamKind === "remote_server" && !fields.host.trim());
  const remote = fields.upstreamKind === "remote_server";
  const sourceTest = !editingProfile
    && candidateTest
    && fields.upstreamKind === "local_listener"
    && String(candidateTest.candidate.port) === fields.port
    ? candidateTest
    : null;
  return (
    <section className="panel profile-editor-panel" aria-labelledby="profile-editor-title">
      <div className="panel-head">
        <h3 id="profile-editor-title">{editingProfile ? tf("Edit “{name}”", { name: editingProfile.displayName }) : t("Add upstream")}</h3>
        <button type="button" className="icon-close" aria-label={t("Close editor")} onClick={closeEditor}><Icon name="close" size={14} /></button>
      </div>
      <fieldset className="editor-fields" disabled={editingLocked}>
        {editingLocked && <div className="notice amber"><Icon name="lock" size={15} /><span>{t("This upstream is in use. Stop TUN before editing or deleting it.")}</span></div>}
        {sourceTest && (
          <div className={`notice ${sourceTest.result?.ok ? "accent" : sourceTest.result || sourceTest.error ? "danger" : ""}`} role="status">
            <span>{!sourceTest.result && !sourceTest.error
              ? t("Testing the discovered listener…")
              : sourceTest.result?.ok
                ? tf("The listener answered · HTTP {code} · {ms} ms. Name it and save.", { code: sourceTest.result.httpCode ?? "—", ms: sourceTest.result.latencyMs ?? "—" })
                : sourceTest.result?.errorCode === "authentication_failed"
                  ? t("The listener needs a credential. Add it below, then save and test.")
                  : t(sourceTest.error?.safeMessage ?? testErrorLabel(sourceTest.result?.errorCode ?? null))}</span>
          </div>
        )}
        <label className="field">
          <span>{t("Display name")}</span>
          <input autoComplete="off" maxLength={64} placeholder={t("For example, Work proxy")} value={fields.name} onChange={(event) => updateFields({ name: event.target.value })} />
        </label>
        <div className="segmented" role="radiogroup" aria-label={t("Upstream type")}>
          <button type="button" role="radio" aria-checked={!remote} onClick={() => updateFields({ upstreamKind: "local_listener", host: "", tls: false, sni: "", certificatePolicy: "strict" })}>{t("Local listener")}</button>
          <button type="button" role="radio" aria-checked={remote} onClick={() => updateFields(fields.host ? { upstreamKind: "remote_server" } : { upstreamKind: "remote_server", port: "1080" })}>{t("Remote server")}</button>
        </div>
        {remote && (
          <label className="field">
            <span>{t("Host or IP address")}</span>
            <input autoComplete="off" maxLength={253} placeholder={t("For example, 192.168.1.20")} value={fields.host} onChange={(event) => updateFields({ host: event.target.value })} />
          </label>
        )}
        <div className="field-row">
          <label className="field">
            <span>{t("Port")}</span>
            <input inputMode="numeric" maxLength={5} value={fields.port} onChange={(event) => updateFields({ port: event.target.value.replace(/\D/g, "") })} />
          </label>
          <div className="field">
            <span>{t("Protocol")}</span>
            <Select<ProxyProtocol> ariaLabel={t("Protocol")} value={fields.protocol} onChange={(protocol) => updateFields({ protocol })} options={[
              { value: "socks5", label: "SOCKS5" },
              { value: "http", label: "HTTP" },
            ]} />
          </div>
        </div>
        {remote && <>
          <div className="field-row">
            <div className="field">
              <span>{t("Transport security")}</span>
              <Select ariaLabel={t("Transport security")} value={fields.tls ? "tls" : "plain"} onChange={(value) => updateFields(value === "tls" ? { tls: true } : { tls: false, sni: "", certificatePolicy: "strict" })} options={[
                { value: "plain", label: t("Plain TCP") },
                { value: "tls", label: "TLS" },
              ]} />
            </div>
            {fields.protocol === "socks5" && (
              <div className="field">
                <span>{t("UDP relay")}</span>
                <Select ariaLabel={t("UDP relay")} value={fields.udp ? "enabled" : "disabled"} onChange={(value) => updateFields({ udp: value === "enabled" })} options={[
                  { value: "enabled", label: t("Enabled") },
                  { value: "disabled", label: t("Disabled") },
                ]} />
              </div>
            )}
          </div>
          {fields.tls && (
            <div className="field-row">
              <label className="field">
                <span>{t("TLS server name")} <em>{t("Optional")}</em></span>
                <input autoComplete="off" maxLength={253} placeholder={fields.host || t("Server hostname")} value={fields.sni} onChange={(event) => updateFields({ sni: event.target.value })} />
              </label>
              <div className="field">
                <span>{t("Certificate verification")}</span>
                <Select<"strict" | "insecure"> ariaLabel={t("Certificate verification")} value={fields.certificatePolicy} onChange={(certificatePolicy) => updateFields({ certificatePolicy })} options={[
                  { value: "strict", label: t("Strict") },
                  { value: "insecure", label: t("Skip verification (unsafe)") },
                ]} />
              </div>
            </div>
          )}
          {fields.tls && fields.certificatePolicy === "insecure" && (
            <div className="notice danger" role="status"><Icon name="alert" size={15} /><span>{t("Certificate verification is disabled for this profile. Network attackers may intercept proxy credentials and traffic.")}</span></div>
          )}
          <p className="field-note">{t("Only this saved host and port are used. TunBridge does not scan the LAN or import proxy subscriptions.")}</p>
        </>}
        <div className="field">
          <span>{t("Credential")}</span>
          <Select<CredentialMode> ariaLabel={t("Credential")} value={fields.credentialMode} onChange={(credentialMode) => updateFields({ credentialMode, username: "", password: "" })} options={[
            editingProfile ? { value: "keep", label: t("Keep saved credential") } : { value: "none", label: t("No credential") },
            { value: "replace", label: t(editingProfile?.hasCredential ? "Replace credential" : "Save credential") },
            ...(editingProfile?.hasCredential ? [{ value: "remove" as const, label: t("Remove credential") }] : []),
          ]} />
        </div>
        {fields.credentialMode === "replace" && (
          <div className="field-row">
            <label className="field">
              <span>{t("Username")}</span>
              <input autoComplete="off" maxLength={128} value={fields.username} onChange={(event) => updateFields({ username: event.target.value })} />
            </label>
            <label className="field">
              <span>{t("Password")}</span>
              <input type="password" autoComplete="new-password" maxLength={256} value={fields.password} onChange={(event) => updateFields({ password: event.target.value })} />
            </label>
          </div>
        )}
        <p className="field-note">{tf("Credentials are stored in {store} and never shown again after saving.", { store: t(credentialStore) })}</p>
        <div className="editor-buttons">
          <button type="button" className="btn btn-primary" disabled={profileBusy || testsBusy || editingLocked || incomplete} onClick={() => void saveProfile(true)}>{t(profileBusy ? "Working…" : "Save and test")}</button>
          <button type="button" className="btn" disabled={profileBusy || editingLocked || incomplete} onClick={() => void saveProfile()}>{t(editingProfile ? "Save changes" : "Save")}</button>
        </div>
      </fieldset>
      {(profileError || profileTestResult) && (
        <div className="panel-body editor-results">
          {profileError && <div className="notice danger" role="status"><Icon name="alert" size={15} /><span><strong>{t(profileError.safeMessage)}</strong>{profileError.code}</span></div>}
          {profileTestResult && (
            <div className={profileTestResult.ok ? "notice accent" : "notice danger"} role="status">
              <Icon name={profileTestResult.ok ? "check" : "alert"} size={15} />
              <span>
                <strong>{t(profileTestResult.ok ? "Saved profile test passed" : "Saved profile test failed")}</strong>
                {profileTestResult.ok
                  ? `HTTP ${profileTestResult.httpCode ?? "—"} · ${profileTestResult.latencyMs ?? "—"} ms`
                  : t(normalizeProxyError({ code: profileTestResult.errorCode }).safeMessage)}
              </span>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
