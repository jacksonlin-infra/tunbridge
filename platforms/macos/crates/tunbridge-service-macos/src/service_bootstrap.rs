#[cfg(not(feature = "macos-development-bootstrap"))]
use crate::listener_policy::load_system_app_requirement;
use crate::{
    dispatcher::{open_system_native_context, HelperLifecycle, MacosServiceContext, SecretSource},
    lifecycle_host::HostError,
    native::XpcCodeRequirement,
    xpc_listener::{run_native_xpc_main, NativeXpcConnectionRegistry},
};
use std::{
    convert::Infallible,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};
#[cfg(feature = "macos-development-bootstrap")]
use std::{
    ffi::CString,
    fs,
    os::unix::ffi::OsStrExt,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

const LEASE_TICK_INTERVAL: Duration = Duration::from_secs(1);
/// A continuous-clock advance this much larger than the uptime advance
/// between two ticks means the system slept in between.
const MIN_DETECTED_SLEEP_SECONDS: u64 = 2;

type SystemContext = MacosServiceContext<
    crate::native_backend::SystemNativeLifecycleHost,
    crate::native::SystemSecretSource,
>;
type SystemRegistry = NativeXpcConnectionRegistry<
    crate::native_backend::SystemNativeLifecycleHost,
    crate::native::SystemSecretSource,
>;

pub struct PreparedSystemXpcService {
    context: Arc<SystemContext>,
    registry: Arc<SystemRegistry>,
    app_requirement: XpcCodeRequirement,
}

pub fn prepare_system_xpc_service() -> Result<PreparedSystemXpcService, HostError> {
    #[cfg(feature = "macos-development-bootstrap")]
    ensure_development_system_layout()?;
    let (app_requirement, context) = prepare_sequence(
        unsafe { libc::geteuid() },
        load_app_requirement_for_bootstrap,
        open_system_native_context,
        monotonic_seconds,
    )?;
    let context = Arc::new(context.with_lease_clock(Arc::new(monotonic_seconds)));
    let registry = Arc::new(NativeXpcConnectionRegistry::new(
        Arc::clone(&context),
        Arc::new(monotonic_seconds),
    ));
    Ok(PreparedSystemXpcService {
        context,
        registry,
        app_requirement,
    })
}

#[cfg(feature = "macos-development-bootstrap")]
fn load_app_requirement_for_bootstrap() -> Result<XpcCodeRequirement, HostError> {
    // The internal ad-hoc candidate changes its executable cdhash whenever it
    // is rebuilt. SMJobBless still authenticates the helper through the
    // embedded authorized-client requirement; the bootstrap command binds
    // the exact app cdhash into the generation policy. Keep the root listener
    // on the identifier-only development requirement so an upgrade is not
    // blocked by the previous candidate's policy file.
    crate::listener_policy::load_development_app_requirement().map_err(|_| HostError::InvalidInput)
}

#[cfg(not(feature = "macos-development-bootstrap"))]
fn load_app_requirement_for_bootstrap() -> Result<XpcCodeRequirement, HostError> {
    match load_system_app_requirement() {
        Ok(requirement) => Ok(requirement),
        Err(_) => Err(HostError::InvalidInput),
    }
}

#[cfg(feature = "macos-development-bootstrap")]
fn ensure_development_system_layout() -> Result<(), HostError> {
    const DIRECTORIES: &[(&str, u32)] = &[
        ("/Library/Application Support/TunBridge", 0o755),
        ("/Library/Application Support/TunBridge/Install", 0o700),
        ("/Library/Application Support/TunBridge/Engine", 0o755),
        ("/Library/Application Support/TunBridge/Runtime", 0o700),
        ("/Library/Application Support/com.tunbridge.desktop", 0o755),
        (
            "/Library/Application Support/com.tunbridge.desktop/helper",
            0o700,
        ),
    ];
    for (raw, mode) in DIRECTORIES {
        let path = Path::new(raw);
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                // `/Library/Application Support` inherits the `admin` group on
                // Monterey. Tighten an existing root-owned product directory
                // to `root:wheel` before validating it, so a clean install does
                // not fail merely because of parent directory group inheritance.
                // Never follow or repair a symlink, and never take ownership of
                // a directory that is not already root-owned.
                if metadata.file_type().is_dir() && metadata.uid() == 0 {
                    enforce_root_wheel(path)?;
                }
                let metadata =
                    fs::symlink_metadata(path).map_err(|_| HostError::JournalUnavailable)?;
                validate_system_directory(&metadata, *mode)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(path).map_err(|_| HostError::JournalUnavailable)?;
                enforce_root_wheel(path)?;
                fs::set_permissions(path, fs::Permissions::from_mode(*mode))
                    .map_err(|_| HostError::JournalUnavailable)?;
                let metadata =
                    fs::symlink_metadata(path).map_err(|_| HostError::JournalUnavailable)?;
                validate_system_directory(&metadata, *mode)?;
            }
            Err(_) => return Err(HostError::JournalUnavailable),
        }
    }
    Ok(())
}

#[cfg(feature = "macos-development-bootstrap")]
fn enforce_root_wheel(path: &Path) -> Result<(), HostError> {
    let encoded = CString::new(path.as_os_str().as_bytes()).map_err(|_| HostError::InvalidInput)?;
    if unsafe { libc::lchown(encoded.as_ptr(), 0, 0) } != 0 {
        return Err(HostError::JournalUnavailable);
    }
    Ok(())
}

#[cfg(feature = "macos-development-bootstrap")]
fn validate_system_directory(metadata: &fs::Metadata, mode: u32) -> Result<(), HostError> {
    if !metadata.file_type().is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o777 != mode
    {
        return Err(HostError::RecoveryRequired);
    }
    Ok(())
}

impl PreparedSystemXpcService {
    pub fn enter(self) -> Result<Infallible, HostError> {
        let _lease_ticker = LeaseTicker::spawn(
            self.context,
            Arc::new(monotonic_seconds),
            Arc::new(continuous_seconds),
            LEASE_TICK_INTERVAL,
        )?;
        run_native_xpc_main(self.registry, self.app_requirement)
    }
}

struct LeaseTicker {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl LeaseTicker {
    fn spawn<L, S>(
        context: Arc<MacosServiceContext<L, S>>,
        clock: Arc<dyn Fn() -> Result<u64, HostError> + Send + Sync>,
        sleep_clock: Arc<dyn Fn() -> Result<u64, HostError> + Send + Sync>,
        interval: Duration,
    ) -> Result<Self, HostError>
    where
        L: HelperLifecycle + 'static,
        S: SecretSource + 'static,
    {
        if interval.is_zero() {
            return Err(HostError::InvalidInput);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::Builder::new()
            .name("tunbridge-lease-ticker".to_owned())
            .spawn(move || {
                let mut sleep_detector = SleepDetector::default();
                while !worker_stop.load(Ordering::Acquire) {
                    thread::park_timeout(interval);
                    if worker_stop.load(Ordering::Acquire) {
                        break;
                    }
                    let result = clock().and_then(|now_tick| {
                        // A failed continuous-clock read only skips sleep
                        // detection; the lease clock still governs expiry.
                        if let Ok(continuous) = sleep_clock() {
                            if sleep_detector.observe(continuous, now_tick) {
                                context.note_system_resume(now_tick)?;
                            }
                        }
                        #[cfg(feature = "macos-development-bootstrap")]
                        let started = std::time::Instant::now();
                        let ticked = context.tick(now_tick);
                        // Request handling waits behind slow ticks; record them
                        // so a lease that expires under load can be explained.
                        #[cfg(feature = "macos-development-bootstrap")]
                        if started.elapsed() >= Duration::from_millis(500) {
                            crate::xpc_listener::debug_log(&format!(
                                "slow-tick tick={now_tick} elapsed-ms={}",
                                started.elapsed().as_millis()
                            ));
                        }
                        ticked
                    });
                    // A failed tick must not take the helper away from the
                    // App: the tunnel stays as it is and the App can still
                    // stop or recover it. The next tick tries again.
                    if let Err(error) = result {
                        #[cfg(feature = "macos-development-bootstrap")]
                        crate::xpc_listener::debug_log(&format!("tick-error error={error:?}"));
                        #[cfg(not(feature = "macos-development-bootstrap"))]
                        let _ = error;
                    }
                }
            })
            .map_err(|_| HostError::BackendUnavailable)?;
        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }
}

impl Drop for LeaseTicker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _ = worker.join();
        }
    }
}

/// Detects a system sleep between two ticks from the divergence of the
/// continuous clock (counts sleep) and the uptime lease clock (does not).
#[derive(Debug, Default)]
struct SleepDetector {
    previous: Option<(u64, u64)>,
}

impl SleepDetector {
    fn observe(&mut self, continuous: u64, uptime: u64) -> bool {
        let slept = self
            .previous
            .is_some_and(|(previous_continuous, previous_uptime)| {
                continuous.saturating_sub(previous_continuous)
                    > uptime
                        .saturating_sub(previous_uptime)
                        .saturating_add(MIN_DETECTED_SLEEP_SECONDS)
            });
        self.previous = Some((continuous, uptime));
        slept
    }
}

/// Lease ticks. The uptime clock pauses while the system sleeps, so a lid
/// close does not expire the lease of an App whose renewals were frozen too.
pub fn monotonic_seconds() -> Result<u64, HostError> {
    clock_seconds(libc::CLOCK_UPTIME_RAW)
}

/// Wall-independent time that keeps counting during sleep. Used only to
/// detect that a sleep happened between two lease ticks.
fn continuous_seconds() -> Result<u64, HostError> {
    clock_seconds(libc::CLOCK_MONOTONIC_RAW)
}

fn clock_seconds(clock: libc::clockid_t) -> Result<u64, HostError> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(clock, &mut value) } != 0
        || value.tv_sec < 0
        || !(0..1_000_000_000).contains(&value.tv_nsec)
    {
        return Err(HostError::BackendUnavailable);
    }
    u64::try_from(value.tv_sec).map_err(|_| HostError::BackendUnavailable)
}

fn prepare_sequence<R, C>(
    effective_uid: u32,
    load_requirement: impl FnOnce() -> Result<R, HostError>,
    open_context: impl FnOnce() -> Result<C, HostError>,
    read_clock: impl FnOnce() -> Result<u64, HostError>,
) -> Result<(R, C), HostError> {
    if effective_uid != 0 {
        return Err(HostError::InvalidInput);
    }
    let requirement = load_requirement()?;
    let context = open_context()?;
    read_clock()?;
    Ok((requirement, context))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle_host::StartMaterial;
    use std::{cell::RefCell, rc::Rc, sync::atomic::AtomicUsize, time::Instant};
    use tunbridge_service::state::Caller;

    struct MemoryLifecycle;

    impl HelperLifecycle for MemoryLifecycle {
        fn start(
            &mut self,
            _profile: &tunbridge_service::protocol::ActiveStartProfile,
            _caller: &Caller,
            _material: StartMaterial,
        ) -> Result<(), HostError> {
            Ok(())
        }

        fn recover(&mut self) -> Result<(), HostError> {
            Ok(())
        }
    }

    struct DeterministicSecrets;

    impl SecretSource for DeterministicSecrets {
        fn next_32(&mut self) -> Result<[u8; 32], HostError> {
            Ok([0x5a; 32])
        }
    }

    #[test]
    fn bootstrap_orders_root_policy_recovery_and_clock_before_listener() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let policy_events = Rc::clone(&events);
        let context_events = Rc::clone(&events);
        let clock_events = Rc::clone(&events);
        let result = prepare_sequence(
            0,
            move || {
                policy_events.borrow_mut().push("policy");
                Ok(1_u8)
            },
            move || {
                context_events.borrow_mut().push("recovery");
                Ok(2_u8)
            },
            move || {
                clock_events.borrow_mut().push("clock");
                Ok(3)
            },
        )
        .unwrap();
        assert_eq!(result, (1, 2));
        assert_eq!(*events.borrow(), ["policy", "recovery", "clock"]);
    }

    #[test]
    fn bootstrap_stops_before_later_dependencies_on_every_failure() {
        let calls = Rc::new(RefCell::new(0));
        let count = Rc::clone(&calls);
        assert!(prepare_sequence(
            501,
            move || {
                *count.borrow_mut() += 1;
                Ok(1_u8)
            },
            || Ok(2_u8),
            || Ok(3),
        )
        .is_err());
        assert_eq!(*calls.borrow(), 0);

        assert!(prepare_sequence(
            0,
            || Err::<u8, _>(HostError::InvalidInput),
            || -> Result<u8, HostError> { panic!("recovery must not run") },
            || panic!("clock must not run"),
        )
        .is_err());
        assert!(prepare_sequence(
            0,
            || Ok(1_u8),
            || Err::<u8, _>(HostError::BackendUnavailable),
            || -> Result<u64, HostError> { panic!("clock must not run") },
        )
        .is_err());
    }

    #[test]
    fn native_monotonic_seconds_is_read_only_and_non_decreasing() {
        let first = monotonic_seconds().unwrap();
        let second = monotonic_seconds().unwrap();
        assert!(second >= first);
        let continuous = continuous_seconds().unwrap();
        // Uptime excludes sleep, so it never runs ahead of the continuous clock.
        assert!(continuous >= first);
    }

    #[test]
    fn sleep_detector_requires_a_clear_continuous_clock_gap() {
        let mut detector = SleepDetector::default();
        assert!(!detector.observe(100, 50));
        assert!(!detector.observe(101, 51));
        assert!(!detector.observe(104, 52));
        // 30 minutes asleep: continuous advanced, uptime advanced one tick.
        assert!(detector.observe(1_904, 53));
        assert!(!detector.observe(1_905, 54));
        // A clock read regression never reports a sleep.
        assert!(!detector.observe(1_000, 55));
    }

    #[test]
    fn lease_ticker_rejects_zero_interval_without_starting_a_thread() {
        let context = Arc::new(MacosServiceContext::stopped(
            MemoryLifecycle,
            DeterministicSecrets,
        ));
        let registry = Arc::new(NativeXpcConnectionRegistry::new(
            Arc::clone(&context),
            Arc::new(|| Ok(1)),
        ));
        drop(registry);
        assert!(matches!(
            LeaseTicker::spawn(
                context,
                Arc::new(|| Ok(1)),
                Arc::new(|| Ok(1)),
                Duration::ZERO
            ),
            Err(HostError::InvalidInput)
        ));
    }

    #[test]
    fn lease_ticker_keeps_ticking_and_serving_after_clock_failure() {
        let context = Arc::new(MacosServiceContext::stopped(
            MemoryLifecycle,
            DeterministicSecrets,
        ));
        let registry = Arc::new(NativeXpcConnectionRegistry::new(
            Arc::clone(&context),
            Arc::new(|| Ok(1)),
        ));
        let clock_calls = Arc::new(AtomicUsize::new(0));
        let worker_calls = Arc::clone(&clock_calls);
        let ticker = LeaseTicker::spawn(
            context,
            Arc::new(move || {
                worker_calls.fetch_add(1, Ordering::SeqCst);
                Err(HostError::BackendUnavailable)
            }),
            Arc::new(|| Ok(1)),
            Duration::from_millis(1),
        )
        .unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        while clock_calls.load(Ordering::SeqCst) < 3 && Instant::now() < deadline {
            thread::yield_now();
        }
        assert!(clock_calls.load(Ordering::SeqCst) >= 3);
        assert!(!registry.is_shut_down());
        drop(ticker);
    }
}
