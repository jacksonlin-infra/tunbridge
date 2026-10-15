// Render a sample config and print it to stdout, for `mihomo -t` validation.
use tunbridge_core::config::render;
use tunbridge_core::profile::{Profile, Protocol, Upstream};

fn main() {
    let mut p = Profile::with_upstream(Upstream {
        host: "127.0.0.1".into(),
        port: 7078,
        protocol: Protocol::Socks5,
        username: None,
        password: None,
        udp: true,
    });
    p.exclude_processes = vec!["ExampleProxy_Mix.bin".into()];
    p.secret = "smoke".into();
    print!("{}", render(&p).unwrap());
}
