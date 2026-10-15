use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use std::time::Duration;
use tunbridge_core::discovery;
use tunbridge_core::platform;
use tunbridge_core::probe::{self, RealFingerprinter};
use tunbridge_core::profile::{Protocol, Upstream};
use tunbridge_core::upstream::{SecretMaterialV2, StandardProtocol};
#[cfg(test)]
use tunbridge_core::CoreError;
use tunbridge_service::{
    protocol::{ActiveStartProfile, Capability, StartProfileV3, StartUpstreamV3},
    state::Phase,
};

#[cfg(windows)]
use tunbridge_service::protocol::ResponseData;
#[cfg(windows)]
use tunbridge_service::windows::{ClientError, ServiceClient};

#[derive(Parser)]
#[command(
    name = "tunbridge",
    version,
    about = "TUN bridge for existing local proxy clients"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Copy, Clone, ValueEnum)]
pub enum ProtoArg {
    Socks5,
    Http,
}

impl From<ProtoArg> for Protocol {
    fn from(p: ProtoArg) -> Self {
        match p {
            ProtoArg::Socks5 => Protocol::Socks5,
            ProtoArg::Http => Protocol::Http,
        }
    }
}

#[derive(Subcommand)]
pub enum Command {
    /// Scan common local ports for a usable proxy client.
    Discover {
        #[arg(long)]
        json: bool,
    },
    /// Test a link through an upstream proxy.
    Test {
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
        #[arg(long, value_enum)]
        protocol: ProtoArg,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        pass: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Start the TUN and route all traffic through the upstream (elevated).
    Up {
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
        #[arg(long, value_enum)]
        protocol: ProtoArg,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        pass: Option<String>,
        #[arg(long = "exclude")]
        exclude: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Stop the TUN and restore the network (elevated).
    Down {
        #[arg(long)]
        json: bool,
    },
    /// Show running status.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Emergency cleanup: kill kernel, remove routes, flush DNS (elevated).
    #[command(name = "panic-reset")]
    PanicReset {
        #[arg(long)]
        json: bool,
    },
}

const TIMEOUT: Duration = Duration::from_secs(4);
const DISCOVERY_FINGERPRINT_TIMEOUT: Duration = Duration::from_millis(500);

pub fn run(cli: Cli) -> i32 {
    match cli.command {
        Command::Discover { json } => cmd_discover(json),
        Command::Test {
            host,
            port,
            protocol,
            user,
            pass,
            json,
        } => cmd_test(host, port, protocol.into(), user, pass, json),
        Command::Up {
            host,
            port,
            protocol,
            user,
            pass,
            exclude,
            json,
        } => cmd_up(host, port, protocol.into(), user, pass, exclude, json),
        Command::Down { json } => cmd_down(json),
        Command::Status { json } => cmd_status(json),
        Command::PanicReset { json } => cmd_panic_reset(json),
    }
}

fn proto_str(p: Protocol) -> &'static str {
    match p {
        Protocol::Socks5 => "socks5",
        Protocol::Http => "http",
    }
}

fn cmd_discover(json: bool) -> i32 {
    let prober = platform::default_port_prober();
    let lister = platform::default_process_lister();
    let fp = RealFingerprinter::new(DISCOVERY_FINGERPRINT_TIMEOUT);
    let report = discovery::discover(
        discovery::DEFAULT_PORTS,
        prober.as_ref(),
        lister.as_ref(),
        &fp,
        Duration::from_millis(300),
    );
    if json {
        println!("{}", serde_json::to_string(&report).unwrap());
    } else if report.candidates.is_empty() {
        println!("No local proxy candidates found.");
    } else {
        println!("{:<7} {:<8} PROCESS", "PORT", "PROTO");
        for c in &report.candidates {
            let proto = c.protocol.map(proto_str).unwrap_or("?");
            let proc = c.process_name.clone().unwrap_or_else(|| "-".into());
            println!("{:<7} {:<8} {}", c.port, proto, proc);
        }
    }
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
    if report.candidates.is_empty() && !report.warnings.is_empty() {
        1
    } else {
        0
    }
}

fn cmd_test(
    host: String,
    port: u16,
    protocol: Protocol,
    user: Option<String>,
    pass: Option<String>,
    json: bool,
) -> i32 {
    let up = Upstream {
        host,
        port,
        protocol,
        username: user,
        password: pass,
        udp: true,
    };
    let r = probe::test_upstream(
        &up,
        probe::DEFAULT_TEST_HOST,
        probe::DEFAULT_TEST_PORT,
        probe::DEFAULT_TEST_PATH,
        TIMEOUT,
    );
    if json {
        println!("{}", serde_json::to_string(&r).unwrap());
    } else if r.ok {
        println!(
            "OK  http={} latency={}ms udp={}",
            r.http_code.unwrap_or(0),
            r.latency_ms.unwrap_or(0),
            r.udp_supported
        );
    } else {
        println!("FAIL {}", r.error.unwrap_or_else(|| "unknown".into()));
    }
    if r.ok {
        0
    } else {
        1
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CliStatus {
    running: bool,
    service_phase: Phase,
    caller_is_owner: bool,
    engine_running: bool,
    service_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CliErrorBody {
    code: String,
    safe_message: String,
    retryable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CliErrorEnvelope {
    ok: bool,
    error: CliErrorBody,
}

trait LifecycleGateway {
    fn require(&self, capability: Capability) -> Result<(), CliErrorBody>;
    fn status(&mut self) -> Result<CliStatus, CliErrorBody>;
    fn start(&mut self, profile: ActiveStartProfile) -> Result<CliStatus, CliErrorBody>;
    fn stop(&mut self) -> Result<CliStatus, CliErrorBody>;
    fn recover(&mut self) -> Result<CliStatus, CliErrorBody>;
}

struct RealServiceGateway {
    #[cfg(windows)]
    client: ServiceClient,
}

impl RealServiceGateway {
    #[cfg(windows)]
    fn connect() -> Result<Self, CliErrorBody> {
        ServiceClient::connect()
            .map(|client| Self { client })
            .map_err(map_client_error)
    }

    #[cfg(not(windows))]
    fn connect() -> Result<Self, CliErrorBody> {
        Err(cli_error(
            "service_unavailable",
            "the TunBridge service is only available on Windows",
            false,
        ))
    }
}

#[cfg(windows)]
impl LifecycleGateway for RealServiceGateway {
    fn require(&self, capability: Capability) -> Result<(), CliErrorBody> {
        self.client
            .capabilities()
            .contains(&capability)
            .then_some(())
            .ok_or_else(capability_error)
    }

    fn status(&mut self) -> Result<CliStatus, CliErrorBody> {
        self.client
            .status()
            .map(response_status)
            .map_err(map_client_error)
    }

    fn start(&mut self, profile: ActiveStartProfile) -> Result<CliStatus, CliErrorBody> {
        self.client
            .start(profile)
            .map(response_status)
            .map_err(map_client_error)
    }

    fn stop(&mut self) -> Result<CliStatus, CliErrorBody> {
        self.client
            .stop()
            .map(response_status)
            .map_err(map_client_error)
    }

    fn recover(&mut self) -> Result<CliStatus, CliErrorBody> {
        self.client
            .recover()
            .map(response_status)
            .map_err(map_client_error)
    }
}

#[cfg(not(windows))]
impl LifecycleGateway for RealServiceGateway {
    fn require(&self, _capability: Capability) -> Result<(), CliErrorBody> {
        unreachable!("connect always fails outside Windows")
    }

    fn status(&mut self) -> Result<CliStatus, CliErrorBody> {
        unreachable!("connect always fails outside Windows")
    }

    fn start(&mut self, _profile: ActiveStartProfile) -> Result<CliStatus, CliErrorBody> {
        unreachable!("connect always fails outside Windows")
    }

    fn stop(&mut self) -> Result<CliStatus, CliErrorBody> {
        unreachable!("connect always fails outside Windows")
    }

    fn recover(&mut self) -> Result<CliStatus, CliErrorBody> {
        unreachable!("connect always fails outside Windows")
    }
}

#[cfg(windows)]
fn map_client_error(error: ClientError) -> CliErrorBody {
    match error {
        ClientError::MissingCapability(_) | ClientError::MissingStatusCapability => CliErrorBody {
            code: "capability_unavailable".into(),
            safe_message: "the installed TunBridge service has not published this capability"
                .into(),
            retryable: false,
        },
        ClientError::Service {
            code,
            message,
            retryable,
        } => CliErrorBody {
            code: serde_json::to_value(code)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| "internal_error".into()),
            safe_message: message,
            retryable,
        },
        ClientError::ServerIdentity(_) => CliErrorBody {
            code: "service_identity_failed".into(),
            safe_message: "the TunBridge service identity could not be verified".into(),
            retryable: false,
        },
        ClientError::Protocol(_)
        | ClientError::ProtocolMismatch(_)
        | ClientError::ResponseMismatch => CliErrorBody {
            code: "service_protocol_error".into(),
            safe_message: "the TunBridge service returned an invalid protocol response".into(),
            retryable: false,
        },
        ClientError::Windows(_) | ClientError::Pipe(_) => CliErrorBody {
            code: "service_unavailable".into(),
            safe_message:
                "the TunBridge service is unavailable; install it or verify that it is running"
                    .into(),
            retryable: true,
        },
    }
}

#[cfg(windows)]
fn response_status(response: ResponseData) -> CliStatus {
    match response {
        ResponseData::Status {
            service_phase,
            caller_is_owner,
            engine_running,
            service_version,
            ..
        } => CliStatus {
            running: engine_running,
            service_phase,
            caller_is_owner,
            engine_running,
            service_version,
        },
        #[allow(unreachable_patterns)]
        _ => unreachable!("lifecycle commands require a status response"),
    }
}

fn cli_error(
    code: impl Into<String>,
    safe_message: impl Into<String>,
    retryable: bool,
) -> CliErrorBody {
    CliErrorBody {
        code: code.into(),
        safe_message: safe_message.into(),
        retryable,
    }
}

#[cfg(any(windows, test))]
fn capability_error() -> CliErrorBody {
    cli_error(
        "capability_unavailable",
        "the installed TunBridge service has not published this capability",
        false,
    )
}

fn emit_error(json: bool, error: CliErrorBody) -> i32 {
    if json {
        println!(
            "{}",
            serde_json::to_string(&CliErrorEnvelope { ok: false, error }).unwrap()
        );
    } else {
        eprintln!("{}: {}", error.code, error.safe_message);
    }
    1
}

fn cmd_status_with_gateway(json: bool, gateway: &mut dyn LifecycleGateway) -> i32 {
    match gateway.status() {
        Ok(s) => {
            if json {
                println!("{}", serde_json::to_string(&s).unwrap());
            } else if s.running {
                println!(
                    "running service_phase={:?} owner={} service_version={}",
                    s.service_phase, s.caller_is_owner, s.service_version
                );
            } else {
                println!(
                    "not running service_phase={:?} service_version={}",
                    s.service_phase, s.service_version
                );
            }
            0
        }
        Err(error) => emit_error(json, error),
    }
}

fn build_start_profile_with_lister(
    host: String,
    port: u16,
    protocol: Protocol,
    user: Option<String>,
    pass: Option<String>,
    mut exclude: Vec<String>,
    lister: &dyn tunbridge_core::platform::ProcessLister,
) -> Result<ActiveStartProfile, CliErrorBody> {
    if !matches!(host.as_str(), "127.0.0.1" | "::1" | "localhost") {
        return Err(cli_error(
            "invalid_profile",
            "the upstream host must be loopback",
            false,
        ));
    }
    let listeners = lister.listeners().map_err(|_| {
        cli_error(
            "upstream_identity_unavailable",
            "the upstream listener identity could not be determined",
            true,
        )
    })?;
    let listener = listeners
        .iter()
        .find(|listener| listener.local_port == port && listener.pid != 0)
        .ok_or_else(|| {
            cli_error(
                "upstream_listener_not_found",
                "no local listening process owns the requested upstream port",
                true,
            )
        })?;
    if !listener.process_name.is_empty() && !exclude.contains(&listener.process_name) {
        exclude.push(listener.process_name.clone());
    }
    let credentials = match (user, pass) {
        (None, None) => None,
        (Some(username), Some(password)) => Some(SecretMaterialV2::basic_auth(username, password)),
        _ => {
            return Err(cli_error(
                "invalid_profile",
                "upstream credentials must include both username and password",
                false,
            ));
        }
    };
    let profile = StartProfileV3 {
        upstream: StartUpstreamV3::LocalListener {
            port,
            protocol: match protocol {
                Protocol::Socks5 => StandardProtocol::Socks5,
                Protocol::Http => StandardProtocol::Http,
            },
            credentials,
            expected_process_id: listener.pid,
        },
        traffic_bypass_domains: Vec::new(),
        traffic_bypass_cidrs: Vec::new(),
        traffic_bypass_process_names: exclude,
    };
    profile.validate().map_err(|_| {
        cli_error(
            "invalid_profile",
            "the requested profile did not pass local validation",
            false,
        )
    })?;
    Ok(profile)
}

fn connect_gateway(json: bool) -> Result<RealServiceGateway, i32> {
    RealServiceGateway::connect().map_err(|error| emit_error(json, error))
}

fn cmd_up(
    host: String,
    port: u16,
    protocol: Protocol,
    user: Option<String>,
    pass: Option<String>,
    exclude: Vec<String>,
    json: bool,
) -> i32 {
    let mut gateway = match connect_gateway(json) {
        Ok(gateway) => gateway,
        Err(exit) => return exit,
    };
    let lister = platform::default_process_lister();
    cmd_up_connected(
        json,
        host,
        port,
        protocol,
        user,
        pass,
        exclude,
        lister.as_ref(),
        &mut gateway,
    )
}

#[allow(clippy::too_many_arguments)]
fn cmd_up_connected(
    json: bool,
    host: String,
    port: u16,
    protocol: Protocol,
    user: Option<String>,
    pass: Option<String>,
    exclude: Vec<String>,
    lister: &dyn tunbridge_core::platform::ProcessLister,
    gateway: &mut dyn LifecycleGateway,
) -> i32 {
    if let Err(error) = gateway.require(Capability::Start) {
        return emit_error(json, error);
    }
    let profile =
        match build_start_profile_with_lister(host, port, protocol, user, pass, exclude, lister) {
            Ok(profile) => profile,
            Err(error) => return emit_error(json, error),
        };
    cmd_up_with_gateway(json, profile, gateway)
}

fn cmd_up_with_gateway(
    json: bool,
    profile: ActiveStartProfile,
    gateway: &mut dyn LifecycleGateway,
) -> i32 {
    match gateway.start(profile) {
        Ok(status) => {
            if json {
                println!("{}", serde_json::to_string(&status).unwrap());
            } else {
                println!("start complete. service_phase={:?}", status.service_phase);
            }
            0
        }
        Err(error) => emit_error(json, error),
    }
}

fn cmd_down(json: bool) -> i32 {
    let mut gateway = match connect_gateway(json) {
        Ok(gateway) => gateway,
        Err(exit) => return exit,
    };
    cmd_down_connected(json, &mut gateway)
}

fn cmd_down_connected(json: bool, gateway: &mut dyn LifecycleGateway) -> i32 {
    if let Err(error) = gateway.require(Capability::Stop) {
        return emit_error(json, error);
    }
    cmd_down_with_gateway(json, gateway)
}

fn cmd_down_with_gateway(json: bool, gateway: &mut dyn LifecycleGateway) -> i32 {
    match gateway.stop() {
        Ok(status) => {
            if json {
                println!("{}", serde_json::to_string(&status).unwrap());
            } else {
                println!("stop complete. service_phase={:?}", status.service_phase);
            }
            0
        }
        Err(error) => emit_error(json, error),
    }
}

fn cmd_status(json: bool) -> i32 {
    let mut gateway = match connect_gateway(json) {
        Ok(gateway) => gateway,
        Err(exit) => return exit,
    };
    cmd_status_with_gateway(json, &mut gateway)
}

fn cmd_panic_reset(json: bool) -> i32 {
    let mut gateway = match connect_gateway(json) {
        Ok(gateway) => gateway,
        Err(exit) => return exit,
    };
    cmd_recover_connected(json, &mut gateway)
}

fn cmd_recover_connected(json: bool, gateway: &mut dyn LifecycleGateway) -> i32 {
    if let Err(error) = gateway.require(Capability::Recover) {
        return emit_error(json, error);
    }
    cmd_recover_with_gateway(json, gateway)
}

fn cmd_recover_with_gateway(json: bool, gateway: &mut dyn LifecycleGateway) -> i32 {
    match gateway.recover() {
        Ok(status) => {
            if json {
                println!("{}", serde_json::to_string(&status).unwrap());
            } else {
                println!(
                    "recovery complete. service_phase={:?}",
                    status.service_phase
                );
            }
            0
        }
        Err(error) => emit_error(json, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunbridge_core::platform::model::Listener;
    use tunbridge_core::platform::ProcessLister;

    struct FakeLister {
        rows: tunbridge_core::Result<Vec<Listener>>,
    }

    struct PanicLister;

    impl ProcessLister for PanicLister {
        fn listeners(&self) -> tunbridge_core::Result<Vec<Listener>> {
            panic!("listener enumeration must not run when Start is unpublished")
        }
    }

    impl ProcessLister for FakeLister {
        fn listeners(&self) -> tunbridge_core::Result<Vec<Listener>> {
            match &self.rows {
                Ok(rows) => Ok(rows.clone()),
                Err(error) => Err(CoreError::Discovery(error.to_string())),
            }
        }
    }

    struct FakeGateway {
        required: Result<(), CliErrorBody>,
        result: Result<CliStatus, CliErrorBody>,
        status_calls: usize,
        start_calls: usize,
        stop_calls: usize,
        recover_calls: usize,
    }

    impl LifecycleGateway for FakeGateway {
        fn require(&self, _capability: Capability) -> Result<(), CliErrorBody> {
            self.required.clone()
        }

        fn status(&mut self) -> Result<CliStatus, CliErrorBody> {
            self.status_calls += 1;
            self.result.clone()
        }

        fn start(&mut self, _profile: ActiveStartProfile) -> Result<CliStatus, CliErrorBody> {
            self.start_calls += 1;
            self.result.clone()
        }

        fn stop(&mut self) -> Result<CliStatus, CliErrorBody> {
            self.stop_calls += 1;
            self.result.clone()
        }

        fn recover(&mut self) -> Result<CliStatus, CliErrorBody> {
            self.recover_calls += 1;
            self.result.clone()
        }
    }

    fn running_status() -> CliStatus {
        CliStatus {
            running: true,
            service_phase: Phase::Running,
            caller_is_owner: true,
            engine_running: true,
            service_version: "0.1.0".into(),
        }
    }

    fn fake_gateway(result: Result<CliStatus, CliErrorBody>) -> FakeGateway {
        FakeGateway {
            required: Ok(()),
            result,
            status_calls: 0,
            start_calls: 0,
            stop_calls: 0,
            recover_calls: 0,
        }
    }

    fn valid_start_profile() -> ActiveStartProfile {
        StartProfileV3 {
            upstream: StartUpstreamV3::LocalListener {
                port: 7078,
                protocol: StandardProtocol::Socks5,
                credentials: None,
                expected_process_id: 7,
            },
            traffic_bypass_domains: Vec::new(),
            traffic_bypass_cidrs: Vec::new(),
            traffic_bypass_process_names: vec!["client.exe".into()],
        }
    }

    #[test]
    fn status_uses_service_gateway_once() {
        let mut gateway = fake_gateway(Ok(running_status()));
        assert_eq!(cmd_status_with_gateway(true, &mut gateway), 0);
        assert_eq!(gateway.status_calls, 1);
    }

    #[test]
    fn status_fails_closed_when_service_is_unavailable() {
        let mut gateway = fake_gateway(Err(CliErrorBody {
            code: "service_unavailable".into(),
            safe_message: "the TunBridge service is unavailable".into(),
            retryable: true,
        }));
        assert_eq!(cmd_status_with_gateway(true, &mut gateway), 1);
        assert_eq!(gateway.status_calls, 1);
    }

    #[test]
    fn lifecycle_commands_use_only_the_service_gateway() {
        let mut gateway = fake_gateway(Ok(running_status()));
        assert_eq!(
            cmd_up_with_gateway(true, valid_start_profile(), &mut gateway),
            0
        );
        assert_eq!(cmd_down_with_gateway(true, &mut gateway), 0);
        assert_eq!(cmd_recover_with_gateway(true, &mut gateway), 0);
        assert_eq!(gateway.start_calls, 1);
        assert_eq!(gateway.stop_calls, 1);
        assert_eq!(gateway.recover_calls, 1);
    }

    #[test]
    fn unpublished_capabilities_fail_before_lifecycle_work() {
        let mut gateway = fake_gateway(Ok(running_status()));
        gateway.required = Err(capability_error());

        assert_eq!(
            cmd_up_connected(
                true,
                "127.0.0.1".into(),
                7078,
                Protocol::Socks5,
                None,
                None,
                Vec::new(),
                &PanicLister,
                &mut gateway,
            ),
            1
        );
        assert_eq!(cmd_down_connected(true, &mut gateway), 1);
        assert_eq!(cmd_recover_connected(true, &mut gateway), 1);
        assert_eq!(gateway.start_calls, 0);
        assert_eq!(gateway.stop_calls, 0);
        assert_eq!(gateway.recover_calls, 0);
    }

    #[test]
    fn profile_auto_excludes_upstream_owner() {
        let lister = FakeLister {
            rows: Ok(vec![Listener {
                local_port: 7078,
                pid: 7,
                process_name: "client.exe".into(),
                process_path: Some("C:\\client.exe".into()),
            }]),
        };
        let profile = build_start_profile_with_lister(
            "127.0.0.1".into(),
            7078,
            Protocol::Socks5,
            None,
            None,
            vec![],
            &lister,
        )
        .unwrap();
        assert!(matches!(
            profile.upstream,
            StartUpstreamV3::LocalListener {
                expected_process_id: 7,
                ..
            }
        ));
        assert_eq!(profile.traffic_bypass_process_names, vec!["client.exe"]);
    }

    #[test]
    fn profile_refuses_to_start_without_anti_recursion_identity() {
        let lister = FakeLister { rows: Ok(vec![]) };
        let error = build_start_profile_with_lister(
            "127.0.0.1".into(),
            7078,
            Protocol::Socks5,
            None,
            None,
            vec![],
            &lister,
        )
        .unwrap_err();
        assert_eq!(error.code, "upstream_listener_not_found");
    }

    #[test]
    fn profile_requires_listener_pid_even_with_explicit_exclude() {
        let lister = FakeLister {
            rows: Err(CoreError::Discovery("access denied".into())),
        };
        let error = build_start_profile_with_lister(
            "localhost".into(),
            7078,
            Protocol::Socks5,
            None,
            None,
            vec!["client.exe".into()],
            &lister,
        )
        .unwrap_err();
        assert_eq!(error.code, "upstream_identity_unavailable");
    }

    #[test]
    fn profile_rejects_unpaired_credentials() {
        let lister = FakeLister {
            rows: Ok(vec![Listener {
                local_port: 7078,
                pid: 7,
                process_name: "client.exe".into(),
                process_path: Some("C:\\client.exe".into()),
            }]),
        };
        let error = build_start_profile_with_lister(
            "127.0.0.1".into(),
            7078,
            Protocol::Socks5,
            Some("user".into()),
            None,
            vec![],
            &lister,
        )
        .unwrap_err();
        assert_eq!(error.code, "invalid_profile");
    }

    #[test]
    fn profile_rejects_remote_upstream() {
        let lister = FakeLister { rows: Ok(vec![]) };
        let error = build_start_profile_with_lister(
            "192.0.2.10".into(),
            1080,
            Protocol::Socks5,
            None,
            None,
            vec!["client.exe".into()],
            &lister,
        )
        .unwrap_err();
        assert_eq!(error.code, "invalid_profile");
    }
}
