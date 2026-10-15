#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tunbridge-service-linux is only supported on Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod linux {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tunbridge_service::protocol::MAX_REQUESTS_PER_CONNECTION;
    use tunbridge_service_linux::{
        serve_connection, LinuxServiceContext, LinuxStatusClient, UnixServiceListener,
    };

    const MAX_CLIENT_WORKERS: usize = 16;
    const FRAME_TIMEOUT: Duration = Duration::from_secs(5);

    pub fn main() {
        let result = match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
            [command] if command == "run" => run_service(),
            [command] if command == "status" => print_status(),
            [command] if command == "recover" => recover_left_behind(),
            _ => {
                eprintln!("usage: tunbridge-service-linux <run|status|recover>");
                Err(())
            }
        };
        if result.is_err() {
            std::process::exit(1);
        }
    }

    fn run_service() -> Result<(), ()> {
        let context = Arc::new(LinuxServiceContext::system().map_err(report_lifecycle_error)?);
        let watchdog_context = Arc::clone(&context);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(1));
            let _ = watchdog_context.tick();
        });
        let listener = UnixServiceListener::bind_system().map_err(report_error)?;
        let active = Arc::new(AtomicUsize::new(0));
        loop {
            // One failed accept must not end the service: the tunnel it
            // watches would be left without its owner.
            let connection = match listener.accept(None, FRAME_TIMEOUT) {
                Ok(connection) => connection,
                Err(error) => {
                    eprintln!("TunBridge Linux service accept failed: {:?}", error.code);
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
            };
            if active
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    (count < MAX_CLIENT_WORKERS).then_some(count + 1)
                })
                .is_err()
            {
                continue;
            }
            let active = Arc::clone(&active);
            let context = Arc::clone(&context);
            std::thread::spawn(move || {
                let _worker = ActiveWorker(active);
                if let Err(error) =
                    serve_connection(connection, context, MAX_REQUESTS_PER_CONNECTION)
                {
                    eprintln!(
                        "TunBridge Linux service connection closed: {:?}",
                        error.code
                    );
                }
            });
        }
    }

    /// Tears down a tunnel the stopped service left running. The engine
    /// survives the service on purpose (KillMode=process); package removal is
    /// the user's explicit decision to end it.
    fn recover_left_behind() -> Result<(), ()> {
        let lifecycle = tunbridge_service_linux::LinuxLifecycle::system();
        lifecycle
            .recover()
            .and_then(|()| lifecycle.remove_traffic_lock())
            .map_err(report_lifecycle_error)
    }

    fn print_status() -> Result<(), ()> {
        let mut client = LinuxStatusClient::connect_system().map_err(report_error)?;
        let status = client.status().map_err(report_error)?;
        let output = serde_json::to_string(&status).map_err(|_| ())?;
        println!("{output}");
        Ok(())
    }

    struct ActiveWorker(Arc<AtomicUsize>);

    impl Drop for ActiveWorker {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::AcqRel);
        }
    }

    fn report_error(error: tunbridge_desktop_contract::adapter::AdapterError) {
        eprintln!("{}", error.safe_message);
    }

    fn report_lifecycle_error(error: tunbridge_service_linux::LifecycleFailure) {
        eprintln!("{}", error.safe_message);
    }
}
