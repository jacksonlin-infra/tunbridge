//! Local, bounded record of tunnel state changes.
//!
//! The service reports only the current state, so the overview could not say
//! when the tunnel was turned on, how long it has been blocked, or what the
//! last session looked like. The Desktop records that itself: the lifecycle
//! commands record what the user did, and the status monitor records what the
//! service did on its own. Nothing is recorded while the App is not running;
//! an `app_started` entry marks each such gap.
//!
//! The log lives in the App's per-user data directory, keeps the newest
//! [`MAX_EVENTS`] entries, holds no addresses, names or credentials (only a
//! saved profile id, which the WebView maps to its display name), and is
//! written atomically.

use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const MAX_EVENTS: usize = 200;
pub const MAX_RETURNED_EVENTS: usize = 100;
pub const FILE_NAME: &str = "tunnel-events.json";
const MAX_FILE_BYTES: u64 = 256 * 1024;
const SCHEMA_VERSION: u16 = 1;

const REASONS: &[&str] = &[
    "engine_exited",
    "upstream_unavailable",
    "controller_unavailable",
    "adapter_missing",
    "runtime_identity_mismatch",
    "lease_expired",
    "connection_storm",
];
const PHASES: &[&str] = &[
    "stopped",
    "starting",
    "running",
    "stopping",
    "recovering",
    "faulted",
    "unavailable",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// The App began observing; anything before it was not recorded.
    AppStarted,
    Started,
    Stopped,
    Blocked,
    Resumed,
    Faulted,
    Recovered,
    /// The service refused or failed a start the user asked for.
    StartFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Actor {
    /// The user did it in this App.
    User,
    /// The service did it on its own.
    Service,
    /// The App found it already so; the time is when it noticed.
    Observed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TunnelEvent {
    pub at_unix_ms: u64,
    pub kind: EventKind,
    pub actor: Actor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_total: Option<u64>,
}

impl TunnelEvent {
    pub fn new(kind: EventKind, actor: Actor) -> Self {
        Self {
            at_unix_ms: now_unix_ms(),
            kind,
            actor,
            reason: None,
            phase: None,
            profile_id: None,
            download_total: None,
            upload_total: None,
        }
    }

    pub fn with_reason(mut self, reason: Option<&str>) -> Self {
        self.reason = reason.map(str::to_owned);
        self
    }

    fn is_valid(&self) -> bool {
        self.at_unix_ms > 0
            && self
                .reason
                .as_deref()
                .is_none_or(|reason| REASONS.contains(&reason))
            && self
                .phase
                .as_deref()
                .is_none_or(|phase| PHASES.contains(&phase))
            && self.profile_id.as_deref().is_none_or(is_profile_id)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredLog {
    schema_version: u16,
    events: Vec<TunnelEvent>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelEventPage {
    schema_version: u16,
    events: Vec<TunnelEvent>,
}

/// What the status monitor saw, reduced to what the log needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedPhase {
    Running,
    Busy,
    Stopped,
    Faulted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    pub phase: ObservedPhase,
    pub phase_name: &'static str,
    pub owned: bool,
    pub degraded: Option<&'static str>,
    pub stop_reason: Option<&'static str>,
}

/// Engine totals restart with each engine generation; the session total is
/// the sum over every generation the App saw.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SessionTraffic {
    generation: Option<String>,
    current_down: u64,
    current_up: u64,
    carried_down: u64,
    carried_up: u64,
}

impl SessionTraffic {
    pub fn sample(&mut self, generation: &str, download_total: u64, upload_total: u64) {
        if self.generation.as_deref() != Some(generation) {
            self.carried_down = self.carried_down.saturating_add(self.current_down);
            self.carried_up = self.carried_up.saturating_add(self.current_up);
            self.generation = Some(generation.to_owned());
        }
        self.current_down = download_total;
        self.current_up = upload_total;
    }

    pub fn totals(&self) -> Option<(u64, u64)> {
        self.generation.as_ref().map(|_| {
            (
                self.carried_down.saturating_add(self.current_down),
                self.carried_up.saturating_add(self.current_up),
            )
        })
    }
}

pub struct EventLog {
    path: Option<PathBuf>,
    events: VecDeque<TunnelEvent>,
    observed: bool,
    running_owned: bool,
    degraded: Option<String>,
    faulted: bool,
    traffic: SessionTraffic,
}

impl EventLog {
    /// Loads the log; a missing, oversized or malformed file starts empty.
    pub fn open(path: Option<PathBuf>) -> Self {
        let events = path.as_deref().map(read_events).unwrap_or_default();
        Self {
            path,
            events,
            observed: false,
            running_owned: false,
            degraded: None,
            faulted: false,
            traffic: SessionTraffic::default(),
        }
    }

    pub fn page(&self) -> TunnelEventPage {
        let skip = self.events.len().saturating_sub(MAX_RETURNED_EVENTS);
        TunnelEventPage {
            schema_version: SCHEMA_VERSION,
            events: self.events.iter().skip(skip).cloned().collect(),
        }
    }

    pub fn sample_traffic(&mut self, generation: &str, download_total: u64, upload_total: u64) {
        self.traffic
            .sample(generation, download_total, upload_total);
    }

    /// The user started the tunnel from this App.
    pub fn user_started(&mut self, profile_id: &str) {
        let profile_id = is_profile_id(profile_id).then(|| profile_id.to_owned());
        self.running_owned = true;
        self.degraded = None;
        self.faulted = false;
        // The monitor may have sampled the new session just before this
        // command returned; that entry is this start.
        if self.claim_recent(EventKind::Started, |event| {
            event.profile_id = profile_id.clone()
        }) {
            return;
        }
        let mut event = TunnelEvent::new(EventKind::Started, Actor::User);
        event.profile_id = profile_id;
        self.traffic = SessionTraffic::default();
        self.push(event);
    }

    /// The service refused or failed a start the user asked for. A failed
    /// start can leave the service faulted with no session to close, so the
    /// recovery that follows is recorded too.
    pub fn user_start_failed(&mut self, profile_id: &str) {
        let mut event = TunnelEvent::new(EventKind::StartFailed, Actor::User);
        event.profile_id = is_profile_id(profile_id).then(|| profile_id.to_owned());
        self.push(event);
    }

    /// The user stopped the tunnel (or quit with "stop TUN").
    pub fn user_closed(&mut self) {
        self.user_ended(EventKind::Stopped);
    }

    /// The user confirmed restoring the previous network after a fault.
    pub fn user_recovered(&mut self) {
        self.user_ended(EventKind::Recovered);
    }

    fn user_ended(&mut self, kind: EventKind) {
        if self.session_open() {
            let event = self.with_traffic(TunnelEvent::new(kind, Actor::User));
            self.close_session();
            self.push(event);
            return;
        }
        if self.faulted {
            // A fault outside a session, such as a failed start.
            self.close_session();
            self.push(TunnelEvent::new(kind, Actor::User));
            return;
        }
        // Already closed: either the monitor noticed this very stop a moment
        // earlier (claim it), or nothing was running (record nothing).
        if !self.claim_recent(EventKind::Stopped, |event| event.kind = kind) {
            self.close_session();
        }
    }

    /// Re-attributes the newest event to the user when it is an `observed`
    /// entry of `kind` from the last few seconds, i.e. the monitor saw the
    /// user's own action before the command finished recording it.
    fn claim_recent(&mut self, kind: EventKind, adjust: impl FnOnce(&mut TunnelEvent)) -> bool {
        const WINDOW_MS: u64 = 15_000;
        let now = now_unix_ms();
        let Some(event) = self.events.back_mut() else {
            return false;
        };
        if event.kind != kind
            || event.actor != Actor::Observed
            || now.saturating_sub(event.at_unix_ms) > WINDOW_MS
        {
            return false;
        }
        event.actor = Actor::User;
        adjust(event);
        if !event.is_valid() {
            return false;
        }
        if let Some(path) = &self.path {
            let _ = write_events(path, &self.events);
        }
        true
    }

    /// Records what changed since the previous sample. `None` means the
    /// service did not answer; nothing is concluded from that.
    pub fn observe(&mut self, observation: Option<Observation>) {
        let Some(observation) = observation else {
            return;
        };
        if !self.observed {
            self.observed = true;
            let mut event = TunnelEvent::new(EventKind::AppStarted, Actor::Observed);
            event.phase = Some(observation.phase_name.to_owned());
            self.push(event);
            // Continue from what the log knew before this App started.
            self.running_owned = self.session_open();
            self.degraded = self.open_block();
        }
        match observation.phase {
            ObservedPhase::Busy => {}
            ObservedPhase::Running => {
                if !observation.owned {
                    // Another user session's tunnel is not ours to record.
                    return;
                }
                if !self.running_owned || !self.session_open() {
                    self.push(TunnelEvent::new(EventKind::Started, Actor::Observed));
                    self.traffic = SessionTraffic::default();
                }
                self.running_owned = true;
                self.faulted = false;
                match (self.degraded.clone(), observation.degraded) {
                    (previous, Some(reason)) if previous.as_deref() != Some(reason) => {
                        self.push(
                            TunnelEvent::new(EventKind::Blocked, Actor::Service)
                                .with_reason(Some(reason)),
                        );
                        self.degraded = Some(reason.to_owned());
                    }
                    (Some(previous), None) => {
                        self.push(
                            TunnelEvent::new(EventKind::Resumed, Actor::Service)
                                .with_reason(Some(&previous)),
                        );
                        self.degraded = None;
                    }
                    _ => {}
                }
            }
            ObservedPhase::Faulted => {
                if !self.faulted && (self.running_owned || self.session_open()) {
                    self.push(
                        TunnelEvent::new(EventKind::Faulted, Actor::Service)
                            .with_reason(observation.stop_reason),
                    );
                }
                self.faulted = true;
                self.degraded = None;
            }
            ObservedPhase::Stopped => {
                if self.session_open() {
                    // A user stop in this App was already recorded and closed
                    // the session. Manual stops clear the service's stop
                    // reason, so a reason means the service decided; without
                    // one, something outside this App stopped it.
                    let actor = if observation.stop_reason.is_some() {
                        Actor::Service
                    } else {
                        Actor::Observed
                    };
                    let event = self.with_traffic(
                        TunnelEvent::new(EventKind::Stopped, actor)
                            .with_reason(observation.stop_reason),
                    );
                    self.push(event);
                }
                self.close_session();
            }
        }
    }

    fn with_traffic(&self, mut event: TunnelEvent) -> TunnelEvent {
        if let Some((down, up)) = self.traffic.totals() {
            event.download_total = Some(down);
            event.upload_total = Some(up);
        }
        event
    }

    fn close_session(&mut self) {
        self.running_owned = false;
        self.degraded = None;
        self.faulted = false;
        self.traffic = SessionTraffic::default();
    }

    /// Whether the newest start, stop or recovery in the log is a start.
    fn session_open(&self) -> bool {
        self.events
            .iter()
            .rev()
            .find(|event| {
                matches!(
                    event.kind,
                    EventKind::Started | EventKind::Stopped | EventKind::Recovered
                )
            })
            .is_some_and(|event| event.kind == EventKind::Started)
    }

    /// The reason of an unresolved block in the open session, if any.
    fn open_block(&self) -> Option<String> {
        self.events
            .iter()
            .rev()
            .find(|event| {
                matches!(
                    event.kind,
                    EventKind::Blocked
                        | EventKind::Resumed
                        | EventKind::Started
                        | EventKind::Stopped
                        | EventKind::Recovered
                )
            })
            .filter(|event| event.kind == EventKind::Blocked)
            .and_then(|event| event.reason.clone())
    }

    fn push(&mut self, event: TunnelEvent) {
        if !event.is_valid() {
            return;
        }
        self.events.push_back(event);
        while self.events.len() > MAX_EVENTS {
            self.events.pop_front();
        }
        if let Some(path) = &self.path {
            let _ = write_events(path, &self.events);
        }
    }
}

fn is_profile_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn read_events(path: &Path) -> VecDeque<TunnelEvent> {
    let Ok(file) = fs::File::open(path) else {
        return VecDeque::new();
    };
    let mut bytes = Vec::new();
    if file
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > MAX_FILE_BYTES
    {
        return VecDeque::new();
    }
    let Ok(stored) = serde_json::from_slice::<StoredLog>(&bytes) else {
        return VecDeque::new();
    };
    if stored.schema_version != SCHEMA_VERSION {
        return VecDeque::new();
    }
    let mut events: VecDeque<_> = stored
        .events
        .into_iter()
        .filter(TunnelEvent::is_valid)
        .collect();
    while events.len() > MAX_EVENTS {
        events.pop_front();
    }
    events
}

fn write_events(path: &Path, events: &VecDeque<TunnelEvent>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_vec(&StoredLog {
        schema_version: SCHEMA_VERSION,
        events: events.iter().cloned().collect(),
    })
    .map_err(std::io::Error::other)?;
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, body)?;
    fs::rename(&temporary, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = "039d9b8de92547547fdce25b7819365c";

    fn running(degraded: Option<&'static str>) -> Option<Observation> {
        Some(Observation {
            phase: ObservedPhase::Running,
            phase_name: "running",
            owned: true,
            degraded,
            stop_reason: None,
        })
    }

    fn stopped(stop_reason: Option<&'static str>) -> Option<Observation> {
        Some(Observation {
            phase: ObservedPhase::Stopped,
            phase_name: "stopped",
            owned: false,
            degraded: None,
            stop_reason,
        })
    }

    fn kinds(log: &EventLog) -> Vec<(EventKind, Actor)> {
        log.events
            .iter()
            .map(|event| (event.kind, event.actor))
            .collect()
    }

    #[test]
    fn records_a_user_session_with_an_outage_once() {
        let mut log = EventLog::open(None);
        log.observe(stopped(None));
        log.user_started(PROFILE);
        log.observe(running(None));
        log.sample_traffic("g1", 100, 10);
        log.observe(running(Some("upstream_unavailable")));
        log.observe(running(Some("upstream_unavailable")));
        log.observe(running(None));
        log.sample_traffic("g2", 50, 5);
        log.user_closed();
        log.observe(stopped(None));
        assert_eq!(
            kinds(&log),
            vec![
                (EventKind::AppStarted, Actor::Observed),
                (EventKind::Started, Actor::User),
                (EventKind::Blocked, Actor::Service),
                (EventKind::Resumed, Actor::Service),
                (EventKind::Stopped, Actor::User),
            ]
        );
        let stop = log.events.back().unwrap();
        assert_eq!(
            (stop.download_total, stop.upload_total),
            (Some(150), Some(15))
        );
        assert_eq!(log.events[1].profile_id.as_deref(), Some(PROFILE));
    }

    #[test]
    fn the_users_action_claims_what_the_monitor_just_saw() {
        let mut log = EventLog::open(None);
        log.observe(stopped(None));
        // The monitor samples between the service acting and the command
        // returning: the start and the stop are each recorded once.
        log.observe(running(None));
        log.user_started(PROFILE);
        log.sample_traffic("g", 42, 4);
        log.observe(stopped(None));
        log.user_closed();
        log.user_closed();
        assert_eq!(
            kinds(&log),
            vec![
                (EventKind::AppStarted, Actor::Observed),
                (EventKind::Started, Actor::User),
                (EventKind::Stopped, Actor::User),
            ]
        );
        assert_eq!(log.events[1].profile_id.as_deref(), Some(PROFILE));
        assert_eq!(log.events[2].download_total, Some(42));
    }

    #[test]
    fn records_a_failed_start_and_the_recovery_after_it() {
        let mut log = EventLog::open(None);
        log.observe(stopped(None));
        log.user_start_failed(PROFILE);
        log.observe(Some(Observation {
            phase: ObservedPhase::Faulted,
            phase_name: "faulted",
            owned: true,
            degraded: None,
            stop_reason: None,
        }));
        log.user_recovered();
        log.user_recovered();
        assert_eq!(
            kinds(&log),
            vec![
                (EventKind::AppStarted, Actor::Observed),
                (EventKind::StartFailed, Actor::User),
                (EventKind::Recovered, Actor::User),
            ]
        );
        assert_eq!(log.events[1].profile_id.as_deref(), Some(PROFILE));
        assert!(!log.session_open());
    }

    #[test]
    fn a_stop_with_nothing_running_records_nothing() {
        let mut log = EventLog::open(None);
        log.observe(stopped(None));
        log.user_closed();
        log.user_recovered();
        assert_eq!(kinds(&log), vec![(EventKind::AppStarted, Actor::Observed)]);
    }

    #[test]
    fn records_a_service_stop_with_its_reason() {
        let mut log = EventLog::open(None);
        log.observe(running(None));
        log.observe(stopped(Some("lease_expired")));
        let stop = log.events.back().unwrap();
        assert_eq!(
            (stop.kind, stop.actor),
            (EventKind::Stopped, Actor::Service)
        );
        assert_eq!(stop.reason.as_deref(), Some("lease_expired"));
    }

    #[test]
    fn a_relaunched_app_continues_the_open_session() {
        let directory = std::env::temp_dir().join(format!("tunbridge-events-{}", now_unix_ms()));
        let path = directory.join(FILE_NAME);
        {
            let mut log = EventLog::open(Some(path.clone()));
            log.observe(stopped(None));
            log.user_started(PROFILE);
            log.observe(running(Some("upstream_unavailable")));
        }
        let mut log = EventLog::open(Some(path.clone()));
        log.observe(running(None));
        let recorded: Vec<_> = kinds(&log).into_iter().skip(3).collect();
        // No second "started": the session from before the relaunch goes on,
        // and the block that ended while the App was away is closed.
        assert_eq!(
            recorded,
            vec![
                (EventKind::AppStarted, Actor::Observed),
                (EventKind::Resumed, Actor::Service),
            ]
        );
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn notices_a_tunnel_it_did_not_see_start() {
        let mut log = EventLog::open(None);
        log.observe(running(None));
        assert_eq!(
            kinds(&log),
            vec![
                (EventKind::AppStarted, Actor::Observed),
                (EventKind::Started, Actor::Observed),
            ]
        );
    }

    #[test]
    fn ignores_unanswered_samples_and_other_sessions() {
        let mut log = EventLog::open(None);
        log.observe(None);
        assert!(log.events.is_empty());
        log.observe(Some(Observation {
            phase: ObservedPhase::Running,
            phase_name: "running",
            owned: false,
            degraded: None,
            stop_reason: None,
        }));
        assert_eq!(kinds(&log), vec![(EventKind::AppStarted, Actor::Observed)]);
    }

    #[test]
    fn a_stop_without_a_reason_happened_outside_this_app() {
        let mut log = EventLog::open(None);
        log.observe(running(None));
        log.observe(stopped(None));
        let stop = log.events.back().unwrap();
        assert_eq!(
            (stop.kind, stop.actor),
            (EventKind::Stopped, Actor::Observed)
        );
    }

    #[test]
    fn records_faults_and_the_users_recovery() {
        let mut log = EventLog::open(None);
        log.observe(running(None));
        let faulted = Some(Observation {
            phase: ObservedPhase::Faulted,
            phase_name: "faulted",
            owned: true,
            degraded: None,
            stop_reason: Some("engine_exited"),
        });
        log.observe(faulted);
        log.observe(faulted);
        log.user_recovered();
        log.observe(stopped(None));
        let recorded: Vec<_> = kinds(&log).into_iter().skip(2).collect();
        assert_eq!(
            recorded,
            vec![
                (EventKind::Faulted, Actor::Service),
                (EventKind::Recovered, Actor::User),
            ]
        );
    }

    #[test]
    fn keeps_a_bounded_valid_log() {
        let mut log = EventLog::open(None);
        for _ in 0..MAX_EVENTS + 20 {
            log.push(TunnelEvent::new(EventKind::Resumed, Actor::Service));
        }
        assert_eq!(log.events.len(), MAX_EVENTS);
        assert_eq!(log.page().events.len(), MAX_RETURNED_EVENTS);
        log.push(TunnelEvent::new(EventKind::Blocked, Actor::Service).with_reason(Some("x")));
        assert_eq!(log.events.len(), MAX_EVENTS);
        log.user_started("not-a-profile-id");
        assert_eq!(log.events.back().unwrap().profile_id, None);
    }

    #[test]
    fn rejects_malformed_or_oversized_files() {
        let directory =
            std::env::temp_dir().join(format!("tunbridge-events-bad-{}", now_unix_ms()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join(FILE_NAME);
        fs::write(&path, b"{not json").unwrap();
        assert!(read_events(&path).is_empty());
        fs::write(&path, vec![b' '; (MAX_FILE_BYTES + 1) as usize]).unwrap();
        assert!(read_events(&path).is_empty());
        fs::write(
            &path,
            br#"{"schemaVersion":1,"events":[{"atUnixMs":5,"kind":"blocked","actor":"service","reason":"bogus"},{"atUnixMs":6,"kind":"started","actor":"user"}]}"#,
        )
        .unwrap();
        assert_eq!(read_events(&path).len(), 1);
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn traffic_survives_engine_restarts() {
        let mut traffic = SessionTraffic::default();
        assert_eq!(traffic.totals(), None);
        traffic.sample("a", 10, 1);
        traffic.sample("a", 30, 3);
        traffic.sample("b", 5, 1);
        assert_eq!(traffic.totals(), Some((35, 4)));
    }
}
