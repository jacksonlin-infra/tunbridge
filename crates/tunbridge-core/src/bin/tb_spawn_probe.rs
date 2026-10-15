//! Test fixture (not shipped): daemonize a long-lived child through
//! `engine::spawn`, print one line, and exit immediately.
//!
//! A parent that captures this process's stdout must observe EOF as soon as this
//! process exits. If the daemonized grandchild inherited the parent's stdout
//! pipe handle, EOF never arrives and the parent hangs forever - the bug this
//! fixture exists to catch. See tests/spawn_no_handle_leak.rs.

use std::path::PathBuf;

fn main() {
    let workdir = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: tb-spawn-probe <workdir>"),
    );
    std::fs::create_dir_all(&workdir).expect("workdir");

    // `ping -n 60 127.0.0.1` is a dependency-free stand-in for the kernel: it
    // lives ~60s, long past this process's exit.
    let daemon = PathBuf::from("C:\\Windows\\System32\\PING.EXE");
    let pid = tunbridge_core::engine::spawn_detached(&daemon, &["-n", "60", "127.0.0.1"], &workdir)
        .expect("spawn daemon");

    println!("{pid}");
    // Exit immediately, leaving the daemon running.
}
