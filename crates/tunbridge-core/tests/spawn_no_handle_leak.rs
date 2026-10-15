//! Regression test for the daemonized-grandchild pipe leak.
//!
//! Symptom this guards against: `tunbridge up` starts the kernel and exits, but
//! any caller capturing its stdout (PowerShell `| Out-String`, CI, the GUI)
//! blocks forever, because Rust spawns with bInheritHandles=TRUE and the
//! detached kernel inherits the caller's stdout pipe, so the pipe never EOFs.
//!
//! `Command::output()` has exactly the same pipe-EOF semantics as PowerShell's
//! pipeline, so it reproduces the hang without elevation or the real kernel.

#![cfg(windows)]

use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[test]
fn spawned_daemon_does_not_hold_parent_stdout_pipe() {
    let probe = env!("CARGO_BIN_EXE_tb-spawn-probe");
    let workdir = std::env::temp_dir().join(format!("tb-leak-{}", std::process::id()));

    let (tx, rx) = mpsc::channel();
    let probe_owned = probe.to_string();
    let workdir_owned = workdir.clone();
    thread::spawn(move || {
        // .output() reads stdout to EOF and waits for exit - it returns only
        // once every write handle to the pipe is closed.
        let result = Command::new(probe_owned).arg(&workdir_owned).output();
        let _ = tx.send(result.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()));
    });

    let outcome = rx.recv_timeout(Duration::from_secs(20));
    let _ = std::fs::remove_dir_all(&workdir);

    let stdout = match outcome {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => panic!("probe failed to run: {e}"),
        Err(_) => panic!(
            "TIMED OUT: parent never saw EOF on the probe's stdout pipe. \
             The daemonized child inherited the parent's stdout handle - this is \
             the `tunbridge up` hang."
        ),
    };

    let daemon_pid: u32 = stdout
        .parse()
        .unwrap_or_else(|_| panic!("probe printed a pid, got {stdout:?}"));
    assert!(daemon_pid > 0, "probe should report the daemon pid");

    // Leave no stray daemon behind.
    let _ = Command::new("taskkill")
        .args(["/F", "/PID", &daemon_pid.to_string()])
        .output();
}
