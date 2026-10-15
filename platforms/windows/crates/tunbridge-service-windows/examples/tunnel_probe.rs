//! Native acceptance probe for the installed Windows service.
//!
//! It speaks to the service pipe exactly like the Desktop does, as the
//! invoking interactive user, so service behaviour can be exercised from a
//! script without the GUI. It never touches the network itself.
//!
//! ```text
//! tunnel_probe status
//! tunnel_probe start <port> <http|socks5> <listener-pid> [hold-seconds]
//! tunnel_probe hold <seconds>        # take the lease over and renew it
//! tunnel_probe stop | recover
//! ```
//!
//! `start` holds and renews the lease for `hold-seconds` (default 0) and then
//! exits without releasing it, which is what a crashed or killed App does.

#[cfg(windows)]
fn main() {
    std::process::exit(match probe::run(std::env::args().skip(1).collect()) {
        Ok(()) => 0,
        Err(message) => {
            eprintln!("tunnel_probe: {message}");
            1
        }
    });
}

#[cfg(not(windows))]
fn main() {
    eprintln!("tunnel_probe only runs on Windows");
    std::process::exit(1);
}

#[cfg(windows)]
mod probe {
    use std::time::{Duration, Instant};
    use tunbridge_core::upstream::StandardProtocol;
    use tunbridge_service::protocol::{ResponseData, StartProfileV3, StartUpstreamV3};
    use tunbridge_service_windows::ServiceClient;

    const RENEW_EVERY: Duration = Duration::from_secs(5);

    pub fn run(arguments: Vec<String>) -> Result<(), String> {
        let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
        match arguments.as_slice() {
            ["status"] => print(client()?.status().map_err(debug)?),
            ["stop"] => print(client()?.stop().map_err(debug)?),
            ["recover"] => print(client()?.recover().map_err(debug)?),
            ["hold", seconds] => hold(number(seconds)?),
            ["start", port, protocol, pid] => start(port, protocol, pid, 0),
            ["start", port, protocol, pid, seconds] => start(port, protocol, pid, number(seconds)?),
            _ => Err("usage: status | start <port> <http|socks5> <pid> [hold-s] | hold <s> | stop | recover".into()),
        }
    }

    fn start(port: &str, protocol: &str, pid: &str, hold_seconds: u64) -> Result<(), String> {
        let profile = StartProfileV3 {
            upstream: StartUpstreamV3::LocalListener {
                port: port.parse().map_err(|_| "bad port")?,
                protocol: match protocol {
                    "http" => StandardProtocol::Http,
                    "socks5" => StandardProtocol::Socks5,
                    _ => return Err("protocol must be http or socks5".into()),
                },
                credentials: None,
                expected_process_id: pid.parse().map_err(|_| "bad pid")?,
            },
            traffic_bypass_domains: Vec::new(),
            traffic_bypass_cidrs: Vec::new(),
            traffic_bypass_process_names: Vec::new(),
        };
        print(client()?.start(profile).map_err(debug)?)?;
        hold(hold_seconds)
    }

    /// Takes the lease (over) and renews it until the deadline, then exits
    /// without releasing it.
    fn hold(seconds: u64) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        let mut grant = client()?.acquire_lease().map_err(debug)?;
        println!("lease acquired");
        while Instant::now() < deadline {
            std::thread::sleep(RENEW_EVERY.min(deadline.saturating_duration_since(Instant::now())));
            if Instant::now() >= deadline {
                break;
            }
            let ResponseData::Lease {
                lease_id,
                lease_nonce,
                next_seq,
                ..
            } = grant
            else {
                return Err("unexpected lease response".into());
            };
            grant = client()?
                .renew_lease(lease_id, lease_nonce, next_seq)
                .map_err(debug)?;
            println!("lease renewed");
        }
        println!("exiting without releasing the lease");
        Ok(())
    }

    fn client() -> Result<ServiceClient, String> {
        ServiceClient::connect().map_err(debug)
    }

    fn print(response: ResponseData) -> Result<(), String> {
        println!("{}", serde_json::to_string(&response).map_err(debug)?);
        Ok(())
    }

    fn number(value: &str) -> Result<u64, String> {
        value.parse().map_err(|_| format!("not a number: {value}"))
    }

    fn debug(error: impl std::fmt::Debug) -> String {
        format!("{error:?}")
    }
}
