#[cfg(windows)]
fn main() {
    #[cfg(feature = "acceptance-m2b5")]
    use tunbridge_service::windows::exact_owned_process_running_for_acceptance;
    #[cfg(feature = "acceptance-lifecycle")]
    use tunbridge_service::windows::native_adapter_instance_id;
    #[cfg(feature = "acceptance-rejection")]
    use tunbridge_service::windows::run_rejection_dispatcher;
    #[cfg(feature = "acceptance-fault-injection")]
    use tunbridge_service::windows::{
        remove_owned_adapter_for_acceptance, terminate_owned_process_for_acceptance,
    };
    use tunbridge_service::{
        protocol::ActiveStartProfile,
        windows::{install, run_dispatcher, uninstall, ServiceClient},
    };

    let command = std::env::args().nth(1).unwrap_or_else(|| "help".into());
    let result = match command.as_str() {
        "run" => run_dispatcher(),
        "install" => install(),
        "uninstall" => uninstall(),
        "status" => match ServiceClient::connect().and_then(|mut client| client.status()) {
            Ok(status) => {
                println!("{}", serde_json::to_string(&status).unwrap());
                return;
            }
            Err(error) => {
                eprintln!("tunbridge-service client: {error}");
                std::process::exit(1);
            }
        },
        "capabilities" => match ServiceClient::connect() {
            Ok(client) => {
                println!("{}", serde_json::to_string(client.capabilities()).unwrap());
                return;
            }
            Err(error) => client_failed(error),
        },
        "start" => {
            let Some(profile_path) = std::env::args().nth(2) else {
                eprintln!("start requires one active StartProfile JSON path");
                std::process::exit(2);
            };
            let profile_text = std::fs::read_to_string(&profile_path).unwrap_or_else(|error| {
                eprintln!("could not read local profile {profile_path}: {error}");
                std::process::exit(2);
            });
            let profile: ActiveStartProfile =
                serde_json::from_str(&profile_text).unwrap_or_else(|error| {
                    eprintln!("active profile JSON is invalid: {error}");
                    std::process::exit(2);
                });
            match ServiceClient::connect().and_then(|mut client| client.start(profile)) {
                Ok(status) => print_json_and_return(&status),
                Err(error) => client_failed(error),
            }
        }
        "stop" => match ServiceClient::connect().and_then(|mut client| client.stop()) {
            Ok(status) => print_json_and_return(&status),
            Err(error) => client_failed(error),
        },
        "recover" => match ServiceClient::connect().and_then(|mut client| client.recover()) {
            Ok(status) => print_json_and_return(&status),
            Err(error) => client_failed(error),
        },
        #[cfg(feature = "acceptance-lifecycle")]
        "inspect-adapter" => match native_adapter_instance_id("tunbridge") {
            Ok(instance_id) => {
                println!(
                    "{}",
                    serde_json::json!({
                        "alias": "tunbridge",
                        "exists": instance_id.is_some(),
                        "expected_instance_id": instance_id
                    })
                );
                return;
            }
            Err(error) => {
                eprintln!("could not inspect the live Windows interface table: {error}");
                std::process::exit(1);
            }
        },
        #[cfg(feature = "acceptance-fault-injection")]
        "acceptance-terminate-owned-process" => match terminate_owned_process_for_acceptance() {
            Ok(outcome) => {
                println!("{}", serde_json::json!({"outcome": format!("{outcome:?}")}));
                return;
            }
            Err(error) => {
                eprintln!("acceptance exact owned-process termination failed: {error}");
                std::process::exit(1);
            }
        },
        #[cfg(feature = "acceptance-fault-injection")]
        "acceptance-remove-owned-adapter" => match remove_owned_adapter_for_acceptance() {
            Ok(()) => {
                println!("{}", serde_json::json!({"removed": true}));
                return;
            }
            Err(error) => {
                eprintln!("acceptance exact owned-adapter removal failed: {error}");
                std::process::exit(1);
            }
        },
        #[cfg(feature = "acceptance-rejection")]
        "acceptance-rejection-server" => run_rejection_dispatcher(),
        #[cfg(feature = "acceptance-m2b5")]
        "acceptance-owned-process-running" => match exact_owned_process_running_for_acceptance() {
            Ok(running) => {
                println!(
                    "{}",
                    serde_json::json!({"exactOwnedProcessRunning": running})
                );
                return;
            }
            Err(error) => {
                eprintln!("acceptance exact owned-process inspection failed: {error}");
                std::process::exit(1);
            }
        },
        #[cfg(feature = "acceptance-m2b5")]
        "acceptance-acquire-and-disconnect" => {
            let mut client = ServiceClient::connect().unwrap_or_else(|error| client_failed(error));
            match client.acquire_lease() {
                Ok(tunbridge_service::protocol::ResponseData::Lease { .. }) => {
                    println!("{}", serde_json::json!({"acquired": true}));
                    return;
                }
                Ok(_) => {
                    eprintln!("lease acquire returned an unexpected response shape");
                    std::process::exit(1);
                }
                Err(error) => client_failed(error),
            }
        }
        #[cfg(feature = "acceptance-m2b5")]
        "acceptance-lease-cycle" => {
            let mut client = ServiceClient::connect().unwrap_or_else(|error| client_failed(error));
            let (lease_id, lease_nonce, next_seq) = match client.acquire_lease() {
                Ok(tunbridge_service::protocol::ResponseData::Lease {
                    lease_id,
                    lease_nonce,
                    next_seq,
                    ..
                }) => (lease_id, lease_nonce, next_seq),
                Ok(_) => {
                    eprintln!("lease acquire returned an unexpected response shape");
                    std::process::exit(1);
                }
                Err(error) => client_failed(error),
            };
            let (lease_id, lease_nonce, next_seq) =
                match client.renew_lease(lease_id, lease_nonce, next_seq) {
                    Ok(tunbridge_service::protocol::ResponseData::Lease {
                        lease_id,
                        lease_nonce,
                        next_seq,
                        ..
                    }) => (lease_id, lease_nonce, next_seq),
                    Ok(_) => {
                        eprintln!("lease renew returned an unexpected response shape");
                        std::process::exit(1);
                    }
                    Err(error) => client_failed(error),
                };
            match client.release_lease(lease_id, lease_nonce, next_seq) {
                Ok(tunbridge_service::protocol::ResponseData::LeaseReleased { released: true }) => {
                    println!(
                        "{}",
                        serde_json::json!({"acquired": true, "renewed": true, "released": true})
                    );
                    return;
                }
                Ok(_) => {
                    eprintln!("lease release returned an unexpected response shape");
                    std::process::exit(1);
                }
                Err(error) => client_failed(error),
            }
        }
        #[cfg(feature = "acceptance-m2b5")]
        "acceptance-lease-negative" => {
            let mut client = ServiceClient::connect().unwrap_or_else(|error| client_failed(error));
            let (lease_id, lease_nonce, next_seq) = match client.acquire_lease() {
                Ok(tunbridge_service::protocol::ResponseData::Lease {
                    lease_id,
                    lease_nonce,
                    next_seq,
                    ..
                }) => (lease_id, lease_nonce, next_seq),
                Ok(_) => {
                    eprintln!("lease acquire returned an unexpected response shape");
                    std::process::exit(1);
                }
                Err(error) => client_failed(error),
            };
            let mut forged_id = lease_id.clone();
            forged_id.replace_range(..1, if forged_id.starts_with('0') { "1" } else { "0" });
            expect_lease_invalid(client.renew_lease(forged_id, lease_nonce.clone(), next_seq));
            let (renewed_id, renewed_nonce, renewed_seq) =
                match client.renew_lease(lease_id.clone(), lease_nonce.clone(), next_seq) {
                    Ok(tunbridge_service::protocol::ResponseData::Lease {
                        lease_id,
                        lease_nonce,
                        next_seq,
                        ..
                    }) => (lease_id, lease_nonce, next_seq),
                    Ok(_) => {
                        eprintln!("lease renew returned an unexpected response shape");
                        std::process::exit(1);
                    }
                    Err(error) => client_failed(error),
                };
            expect_lease_invalid(client.renew_lease(lease_id, lease_nonce, next_seq));
            match client.release_lease(renewed_id.clone(), renewed_nonce.clone(), renewed_seq) {
                Ok(tunbridge_service::protocol::ResponseData::LeaseReleased { released: true }) => {
                }
                Ok(_) => {
                    eprintln!("lease release returned an unexpected response shape");
                    std::process::exit(1);
                }
                Err(error) => client_failed(error),
            }
            expect_lease_invalid(client.release_lease(renewed_id, renewed_nonce, renewed_seq));
            println!(
                "{}",
                serde_json::json!({
                    "forgedRejected": true,
                    "replayRejected": true,
                    "duplicateReleaseRejected": true
                })
            );
            return;
        }
        "help" | "--help" | "-h" => {
            #[cfg(feature = "acceptance-lifecycle")]
            println!("tunbridge-service <run|install|uninstall|status|capabilities|start|stop|recover|inspect-adapter>");
            #[cfg(feature = "acceptance-fault-injection")]
            println!(
                "acceptance-only: acceptance-terminate-owned-process|acceptance-remove-owned-adapter"
            );
            #[cfg(feature = "acceptance-rejection")]
            println!("acceptance-only: acceptance-rejection-server");
            #[cfg(feature = "acceptance-m2b5")]
            println!("acceptance-only: acceptance-owned-process-running|acceptance-acquire-and-disconnect|acceptance-lease-cycle|acceptance-lease-negative");
            #[cfg(not(feature = "acceptance-lifecycle"))]
            println!(
                "tunbridge-service <run|install|uninstall|status|capabilities|start|stop|recover>"
            );
            println!("start <active-start-profile.json>");
            println!("install only accepts Program Files\\TunBridge\\tunbridge-service.exe");
            return;
        }
        _ => {
            eprintln!("unknown command: {command}");
            std::process::exit(2);
        }
    };

    if let Err(error) = result {
        eprintln!("tunbridge-service: {error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn print_json_and_return(value: &impl serde::Serialize) -> ! {
    println!("{}", serde_json::to_string(value).unwrap());
    std::process::exit(0);
}

#[cfg(windows)]
fn client_failed(error: tunbridge_service::windows::ClientError) -> ! {
    #[cfg(feature = "acceptance-fault-injection")]
    if let tunbridge_service::windows::ClientError::Service {
        code,
        message,
        retryable,
    } = &error
    {
        // Windows PowerShell 5 wraps native stderr in a NativeCommandError
        // record and may insert line breaks plus call-site metadata. Emit the
        // acceptance-only machine envelope on stdout while retaining the
        // nonzero process exit code; default builds keep their normal stderr.
        println!(
            "{}",
            serde_json::json!({
                "ok": false,
                "error": {
                    "code": code,
                    "safe_message": message,
                    "retryable": retryable
                }
            })
        );
        std::process::exit(1);
    }
    eprintln!("tunbridge-service client: {error}");
    std::process::exit(1);
}

#[cfg(all(windows, feature = "acceptance-m2b5"))]
fn expect_lease_invalid(
    result: Result<
        tunbridge_service::protocol::ResponseData,
        tunbridge_service::windows::ClientError,
    >,
) {
    if !matches!(
        result,
        Err(tunbridge_service::windows::ClientError::Service {
            code: tunbridge_service::protocol::ErrorCode::LeaseInvalid,
            ..
        })
    ) {
        eprintln!("acceptance lease negative case was not rejected as lease_invalid");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("tunbridge-service is only supported on Windows");
    std::process::exit(1);
}
