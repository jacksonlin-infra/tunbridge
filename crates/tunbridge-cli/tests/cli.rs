use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn help_lists_all_six_verbs() {
    let mut cmd = Command::cargo_bin("tunbridge").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("discover"))
        .stdout(predicate::str::contains("test"))
        .stdout(predicate::str::contains("up"))
        .stdout(predicate::str::contains("down"))
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("panic-reset"));
}

#[test]
fn status_json_fails_closed_when_service_is_unavailable() {
    let dir = std::env::temp_dir().join(format!("tb-cli-status-{}", std::process::id()));
    let mut cmd = Command::cargo_bin("tunbridge").unwrap();
    cmd.env("LOCALAPPDATA", &dir);
    cmd.args(["status", "--json"]);
    cmd.assert()
        .failure()
        .stdout(predicate::str::contains("\"ok\":false"))
        .stdout(predicate::str::contains("\"code\":\"service_unavailable\""));
}

#[test]
fn up_fails_closed_when_service_is_unavailable() {
    let dir = std::env::temp_dir().join(format!("tb-cli-up-{}", std::process::id()));
    let mut cmd = Command::cargo_bin("tunbridge").unwrap();
    cmd.env("LOCALAPPDATA", &dir);
    cmd.args([
        "up",
        "--host",
        "127.0.0.1",
        "--port",
        "7078",
        "--protocol",
        "socks5",
    ]);
    let assertion = cmd
        .assert()
        .failure()
        .stderr(predicate::str::contains("service_unavailable"));
    #[cfg(windows)]
    assertion.stderr(predicate::str::contains("service is unavailable"));
    #[cfg(not(windows))]
    assertion.stderr(predicate::str::contains(
        "service is only available on Windows",
    ));
}

#[test]
fn stop_and_recover_fail_closed_when_service_is_unavailable() {
    for verb in ["down", "panic-reset"] {
        let mut cmd = Command::cargo_bin("tunbridge").unwrap();
        cmd.args([verb, "--json"]);
        cmd.assert()
            .failure()
            .stdout(predicate::str::contains("\"ok\":false"))
            .stdout(predicate::str::contains("\"code\":\"service_unavailable\""));
    }
}
