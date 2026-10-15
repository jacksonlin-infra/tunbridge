#[cfg(target_os = "macos")]
use std::{
    env, process, thread,
    time::{Duration, Instant},
};
#[cfg(target_os = "macos")]
use tunbridge_service::{
    protocol::{StartProfile, StartProfileV3, StartUpstreamV3, UpstreamProtocol},
    state::Caller,
};
#[cfg(target_os = "macos")]
use tunbridge_service_macos::{
    baseline::native_network_baseline,
    controller::TcpControllerTransport,
    controller_owner::NativeControllerOwnerVerifier,
    journal::MacosOwnedJournal,
    lifecycle_host::{HostError, OwnedJournal, StartMaterial},
    native::native_route_snapshot,
    native_backend::open_system_native_lifecycle,
    native_engine::NativeEngineLifecycle,
    native_observability::NativeOwnedControllerSource,
    native_start::verify_native_upstream,
    native_tun::{NativeTunVerifier, SystemInterfaceInventorySource},
    observability::OwnedControllerSource,
};

#[cfg(target_os = "macos")]
fn main() {
    if unsafe { libc::geteuid() } != 0 {
        fail("the development core harness must run as root");
    }
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let result = match arguments.first().map(String::as_str) {
        Some("baseline") if arguments.len() == 1 => baseline(),
        Some("status") if arguments.len() == 1 => status(),
        Some("recover") if arguments.len() == 1 => recover(),
        Some("routes") if arguments.len() == 1 => routes(),
        Some("connections") if arguments.len() == 1 => connections(),
        Some("preflight") => preflight(&arguments[1..]),
        Some("engine-preflight") => engine_preflight(&arguments[1..]),
        Some("tun-preflight") => tun_preflight(&arguments[1..]),
        Some("start") => start(&arguments[1..]),
        _ => Err("usage: tunbridge-macos-core-harness baseline|status|recover|preflight <uid> <session> <pid> <port> <http|socks5>|start <uid> <session> <pid> <port> <http|socks5>"),
    };
    if let Err(message) = result {
        fail(message);
    }
}

#[cfg(target_os = "macos")]
fn connections() -> Result<(), &'static str> {
    let record = MacosOwnedJournal::open_system()
        .and_then(|journal| journal.load())
        .map_err(map_host)?
        .ok_or("owned run unavailable")?;
    let mut source = NativeOwnedControllerSource::new(
        record,
        TcpControllerTransport,
        NativeControllerOwnerVerifier,
    )
    .map_err(|_| "owned controller unavailable")?;
    let payload = source
        .connections()
        .map_err(|_| "owned connections unavailable")?;
    let value: serde_json::Value =
        serde_json::from_slice(&payload).map_err(|_| "invalid connections payload")?;
    let upload = value.get("uploadTotal").and_then(serde_json::Value::as_u64);
    let download = value
        .get("downloadTotal")
        .and_then(serde_json::Value::as_u64);
    let empty = Vec::new();
    let connections = match value.get("connections") {
        Some(serde_json::Value::Array(connections)) => connections,
        Some(serde_json::Value::Null) | None => &empty,
        _ => return Err("invalid connections payload"),
    };
    let count = connections.len();
    println!(
        "connections=ok count={count} upload_total={} download_total={}",
        upload.unwrap_or_default(),
        download.unwrap_or_default()
    );
    for connection in connections.iter().take(8) {
        let metadata = connection
            .get("metadata")
            .unwrap_or(&serde_json::Value::Null);
        println!(
            "connection process={} host={} destination={}:{} rule={}",
            metadata
                .get("process")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
            metadata
                .get("host")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
            metadata
                .get("destinationIP")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
            metadata
                .get("destinationPort")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
            connection
                .get("rule")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn routes() -> Result<(), &'static str> {
    let snapshot = native_route_snapshot().map_err(|_| "native route snapshot unavailable")?;
    println!("{snapshot:#?}");
    Ok(())
}

#[cfg(target_os = "macos")]
fn baseline() -> Result<(), &'static str> {
    let baseline = native_network_baseline().map_err(|_| "network baseline unavailable")?;
    println!(
        "baseline=ok interface_index={} gateway={} dns_service={} dns_mode={:?} preexisting_utuns={}",
        baseline.default_interface_index,
        baseline.default_gateway,
        baseline.dns.network_service_id,
        baseline.dns.mode,
        baseline.preexisting_utuns.len()
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn status() -> Result<(), &'static str> {
    let host = open_system_native_lifecycle().map_err(map_host)?;
    match host.owned_record().map_err(map_host)? {
        Some(record) => println!(
            "status=owned stage={:?} run_id={} engine_pid={} tun={} routes={} dns_applied={}",
            record.stage,
            record.run_id,
            record.engine.as_ref().map_or(0, |value| value.pid),
            record
                .tun
                .as_ref()
                .map_or("none", |value| value.interface_name.as_str()),
            record.route_deltas.len(),
            record.planned_dns_sha256.is_some()
        ),
        None => println!("status=clean"),
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn recover() -> Result<(), &'static str> {
    let mut host = open_system_native_lifecycle().map_err(map_host)?;
    host.recover().map_err(map_host)?;
    if host.owned_record().map_err(map_host)?.is_some() {
        return Err("recovery left an owned journal record");
    }
    println!("recover=ok status=clean");
    Ok(())
}

#[cfg(target_os = "macos")]
fn start(arguments: &[String]) -> Result<(), &'static str> {
    let (caller, profile) = request(arguments)?;
    let credentials = match (&profile.username, &profile.password) {
        (Some(username), Some(password)) => Some(
            tunbridge_core::upstream::SecretMaterialV2::basic_auth(username, password),
        ),
        (None, None) => None,
        _ => return Err("proxy credentials must provide both username and password"),
    };
    let active_profile = StartProfileV3 {
        upstream: StartUpstreamV3::LocalListener {
            port: profile.upstream_port,
            protocol: match profile.protocol {
                UpstreamProtocol::Http => tunbridge_core::upstream::StandardProtocol::Http,
                UpstreamProtocol::Socks5 => tunbridge_core::upstream::StandardProtocol::Socks5,
            },
            credentials,
            expected_process_id: profile.upstream_process_id,
        },
        traffic_bypass_domains: profile.bypass_domains.clone(),
        traffic_bypass_cidrs: profile.bypass_cidrs.clone(),
        traffic_bypass_process_names: profile.bypass_process_names.clone(),
    };
    let mut host = open_system_native_lifecycle().map_err(map_host)?;
    host.start(
        &active_profile,
        &caller,
        StartMaterial {
            run_id: random_lower_hex::<16>()?,
            controller_secret: random_lower_hex::<32>()?,
        },
    )
    .map_err(map_host)?;
    let record = host
        .owned_record()
        .map_err(map_host)?
        .ok_or("start completed without an owned record")?;
    println!(
        "start=ok stage={:?} engine_pid={} tun={} routes={} dns_applied={}",
        record.stage,
        record.engine.as_ref().map_or(0, |value| value.pid),
        record
            .tun
            .as_ref()
            .map_or("none", |value| value.interface_name.as_str()),
        record.route_deltas.len(),
        record.planned_dns_sha256.is_some()
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn preflight(arguments: &[String]) -> Result<(), &'static str> {
    let (caller, profile) = request(arguments)?;
    let baseline = native_network_baseline().map_err(|_| "preflight baseline unavailable")?;
    println!(
        "preflight=baseline_ok interface_index={} preexisting_utuns={}",
        baseline.default_interface_index,
        baseline.preexisting_utuns.len()
    );
    let (_, upstream) =
        verify_native_upstream(&profile, &caller).map_err(|_| "preflight upstream unavailable")?;
    println!(
        "preflight=upstream_ok pid={} start_time_ns={} file_id={} process={}",
        upstream.identity.pid,
        upstream.identity.start_time_ns,
        upstream.identity.executable_file_id,
        upstream.process_name
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn engine_preflight(arguments: &[String]) -> Result<(), &'static str> {
    let (caller, profile) = request(arguments)?;
    let baseline =
        native_network_baseline().map_err(|_| "engine preflight baseline unavailable")?;
    let (_, upstream) = verify_native_upstream(&profile, &caller)
        .map_err(|_| "engine preflight upstream unavailable")?;
    let mut engine = NativeEngineLifecycle::default();
    let identity = engine
        .spawn_verified(
            &profile,
            &caller,
            &baseline,
            &upstream.identity,
            &random_lower_hex::<16>()?,
            &random_lower_hex::<32>()?,
        )
        .map_err(|_| "engine preflight spawn unavailable")?;
    engine
        .abort_suspended(&identity)
        .map_err(|_| "engine preflight cleanup unavailable")?;
    println!(
        "engine_preflight=ok pid={} file_id={} configured_device={}",
        identity.pid,
        identity.executable_file_id,
        engine.configured_device().unwrap_or("clean")
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn tun_preflight(arguments: &[String]) -> Result<(), &'static str> {
    let (caller, profile) = request(arguments)?;
    let baseline = native_network_baseline().map_err(|_| "TUN preflight baseline unavailable")?;
    let (_, upstream) = verify_native_upstream(&profile, &caller)
        .map_err(|_| "TUN preflight upstream unavailable")?;
    let run_id = random_lower_hex::<16>()?;
    let controller_secret = random_lower_hex::<32>()?;
    let mut engine = NativeEngineLifecycle::default();
    let identity = engine
        .spawn_verified(
            &profile,
            &caller,
            &baseline,
            &upstream.identity,
            &run_id,
            &controller_secret,
        )
        .map_err(|_| "TUN preflight spawn unavailable")?;
    if engine.resume(&identity).is_err() {
        let _ = engine.abort_suspended(&identity);
        return Err("TUN preflight resume unavailable");
    }
    let configured_device = engine
        .configured_device()
        .ok_or("TUN preflight device unavailable")?
        .to_owned();
    let mut verifier = NativeTunVerifier::<
        TcpControllerTransport,
        NativeControllerOwnerVerifier,
        SystemInterfaceInventorySource,
    >::default();
    let started = Instant::now();
    let deadline = started + Duration::from_secs(15);
    let mut first_error = None;
    let result = loop {
        match verifier.verify(&baseline, &identity, &controller_secret, &configured_device) {
            Ok(tun) => break Ok(tun),
            Err(error) if Instant::now() < deadline => {
                if first_error.is_none() {
                    eprintln!("tun_preflight_waiting first_error={error:?}");
                    first_error = Some(error);
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => break Err(error),
        }
    };
    let cleanup = engine.terminate_running(&identity);
    let tun = result.map_err(|error| {
        eprintln!("tun_preflight_failed final_error={error:?}");
        "TUN preflight verification unavailable"
    })?;
    cleanup.map_err(|_| "TUN preflight cleanup unavailable")?;
    println!(
        "tun_preflight=ok engine_pid={} interface={} interface_index={} ready_ms={}",
        identity.pid,
        tun.interface_name,
        tun.interface_index,
        started.elapsed().as_millis()
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn request(arguments: &[String]) -> Result<(Caller, StartProfile), &'static str> {
    if arguments.len() != 5 {
        return Err("operation requires uid session pid port protocol");
    }
    let uid = parse_nonzero(&arguments[0])?;
    let session = parse_nonzero(&arguments[1])?;
    let pid = parse_nonzero(&arguments[2])?;
    let port = arguments[3]
        .parse::<u16>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or("invalid port")?;
    let protocol = match arguments[4].as_str() {
        "http" => UpstreamProtocol::Http,
        "socks5" => UpstreamProtocol::Socks5,
        _ => return Err("invalid protocol"),
    };
    let caller = Caller {
        principal_id: format!("macos:{uid}:DEVELOP123:com.tunbridge.desktop"),
        session_id: session,
        is_admin: false,
    };
    let bypass_cidrs = env::var("TUNBRIDGE_DEV_BYPASS_CIDRS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let username = env::var("TUNBRIDGE_DEV_PROXY_USERNAME")
        .ok()
        .filter(|value| !value.is_empty());
    let password = env::var("TUNBRIDGE_DEV_PROXY_PASSWORD")
        .ok()
        .filter(|value| !value.is_empty());
    let profile = StartProfile {
        upstream_host: "127.0.0.1".into(),
        upstream_port: port,
        protocol,
        username,
        password,
        upstream_process_id: pid,
        bypass_domains: Vec::new(),
        bypass_cidrs,
        bypass_process_names: Vec::new(),
    };
    Ok((caller, profile))
}

#[cfg(target_os = "macos")]
fn parse_nonzero(value: &str) -> Result<u32, &'static str> {
    value
        .parse::<u32>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or("invalid nonzero integer")
}

#[cfg(target_os = "macos")]
fn random_lower_hex<const N: usize>() -> Result<String, &'static str> {
    let mut bytes = [0_u8; N];
    if unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
        return Err("secure random source unavailable");
    }
    Ok(bytes.iter().map(|value| format!("{value:02x}")).collect())
}

#[cfg(target_os = "macos")]
fn map_host(error: HostError) -> &'static str {
    match error {
        HostError::InvalidInput => "native lifecycle rejected input",
        HostError::JournalUnavailable => "native lifecycle journal unavailable",
        HostError::BackendUnavailable => "native lifecycle backend unavailable",
        HostError::RecoveryRequired => "native lifecycle requires recovery",
    }
}

#[cfg(target_os = "macos")]
fn fail(message: &str) -> ! {
    eprintln!("error: {message}");
    process::exit(1)
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("The TunBridge macOS core harness can only run on macOS.");
    std::process::exit(1);
}
