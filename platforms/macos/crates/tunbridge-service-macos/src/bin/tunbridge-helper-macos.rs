#[cfg(all(target_os = "macos", feature = "macos-xpc-listener"))]
fn main() {
    match tunbridge_service_macos::service_bootstrap::prepare_system_xpc_service() {
        Ok(service) => match service.enter() {
            Ok(never) => match never {},
            Err(error) => exit_unavailable_with(error),
        },
        Err(error) => exit_unavailable_with(error),
    }
}

#[cfg(all(target_os = "macos", not(feature = "macos-xpc-listener")))]
fn main() {
    if tunbridge_service_macos::native::helper_scaffold_main().is_err() {
        exit_unavailable();
    }
}

#[cfg(all(target_os = "macos", not(feature = "macos-xpc-listener")))]
fn exit_unavailable() -> ! {
    eprintln!("The TunBridge macOS helper is unavailable.");
    std::process::exit(1);
}

#[cfg(all(target_os = "macos", feature = "macos-xpc-listener"))]
fn exit_unavailable_with(error: tunbridge_service_macos::lifecycle_host::HostError) -> ! {
    eprintln!("The TunBridge macOS helper is unavailable: {error:?}");
    std::process::exit(1);
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("The TunBridge macOS helper can only run on macOS.");
    std::process::exit(1);
}
