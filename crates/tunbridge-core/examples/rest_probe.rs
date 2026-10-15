// Probe the engine REST client against a live controller.
// usage: rest_probe <controller> <secret>
use std::time::Duration;
use tunbridge_core::engine;

fn main() {
    let controller = std::env::args().nth(1).expect("controller");
    let secret = std::env::args().nth(2).unwrap_or_default();
    let t = Duration::from_secs(2);

    match engine::rest_version(&controller, &secret, t) {
        Ok(v) => println!("rest_version   OK  -> {v}"),
        Err(e) => println!("rest_version   ERR -> {e}"),
    }
    match engine::rest_connections(&controller, &secret, t) {
        Ok(c) => println!(
            "rest_conns     OK  -> count={} down={} up={}",
            c.count, c.download_total, c.upload_total
        ),
        Err(e) => println!("rest_conns     ERR -> {e}"),
    }
}
