#[test]
#[ignore] // requires the real binary; run with --ignored
fn real_engine_reports_version() {
    let path = tunbridge_core::engine::locate().expect("engine present");
    let v = tunbridge_core::engine::version(&path).expect("version");
    assert!(v.starts_with('v'), "got {v}");
}

#[test]
#[ignore] // requires the real binary; run with --ignored
fn real_engine_accepts_rendered_config() {
    use std::process::Command;
    use tunbridge_core::profile::{Profile, Protocol, Upstream};

    let engine = tunbridge_core::engine::locate().expect("engine present");
    let mut profile = Profile::with_upstream(Upstream {
        host: "127.0.0.1".into(),
        port: 7078,
        protocol: Protocol::Socks5,
        username: None,
        password: None,
        udp: true,
    });
    profile.exclude_processes = vec!["smoke-client.exe".into()];
    profile.secret = "engine-smoke".into();
    let yaml = tunbridge_core::config::render(&profile).expect("render config");

    let dir = std::env::temp_dir().join(format!("tunbridge-engine-smoke-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create smoke directory");
    let config = dir.join("config.yaml");
    std::fs::write(&config, yaml).expect("write smoke config");

    let output = Command::new(&engine)
        .args(["-t", "-f"])
        .arg(&config)
        .output()
        .expect("run engine config check");
    let diagnostics = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        output.status.success(),
        "engine rejected config: {diagnostics}"
    );
}
