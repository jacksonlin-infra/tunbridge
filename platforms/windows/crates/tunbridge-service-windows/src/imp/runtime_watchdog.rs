use crate::watchdog::{HealthSignal, RuntimeObservation};

use super::{
    adapter::native_adapter_instance_id,
    load_owned_engine,
    owned::{inspect_owned_record, persist_owned_engine, OwnedRecordState},
    upstream::{
        sample_loopback_listener_owner, sample_recorded_upstream, RecordedUpstreamSample,
        RestartedUpstream,
    },
    OwnedEngineStage,
};

pub(super) struct RuntimeSample {
    pub observation: RuntimeObservation,
    /// The recorded local upstream client restarted from its exact recorded
    /// executable. The caller rebinds the record only while Running.
    pub restarted_upstream: Option<RestartedUpstream>,
}

pub(super) fn sample_runtime(include_slow_signals: bool) -> RuntimeSample {
    let mut restarted_upstream = None;
    let observation = sample_runtime_observation(include_slow_signals, &mut restarted_upstream);
    RuntimeSample {
        observation,
        restarted_upstream,
    }
}

/// Persists the restarted upstream identity into the exact running record.
/// Returns false when the record no longer matches the sampled session.
pub(super) fn persist_restarted_upstream(restarted: RestartedUpstream) -> bool {
    let Ok(Some(mut record)) = load_owned_engine() else {
        return false;
    };
    if record.stage != OwnedEngineStage::Running
        || record.remote_upstream
        || record.upstream_pid != restarted.previous_pid
    {
        return false;
    }
    record.upstream_pid = restarted.pid;
    record.upstream_creation_time = restarted.creation_time;
    persist_owned_engine(&record).is_ok()
}

fn sample_runtime_observation(
    include_slow_signals: bool,
    restarted_upstream: &mut Option<RestartedUpstream>,
) -> RuntimeObservation {
    let Some(record) = load_owned_engine().ok().flatten() else {
        return unknown_observation(include_slow_signals);
    };
    if record.stage != OwnedEngineStage::Running {
        return unknown_observation(include_slow_signals);
    }

    let engine = match inspect_owned_record(&record) {
        Ok(OwnedRecordState::Running) => HealthSignal::Healthy,
        Ok(OwnedRecordState::Exited) => HealthSignal::Unhealthy,
        Err(_) => HealthSignal::Unknown,
    };
    if !include_slow_signals {
        return RuntimeObservation::engine_only(engine);
    }

    let upstream = if record.remote_upstream {
        HealthSignal::Healthy
    } else {
        match sample_recorded_upstream(
            &record.upstream_host,
            record.upstream_port,
            record.upstream_pid,
            record.upstream_creation_time,
            &record.upstream_image_path,
        ) {
            RecordedUpstreamSample::Signal(signal) => signal,
            RecordedUpstreamSample::Restarted(restarted) => {
                *restarted_upstream = Some(restarted);
                // Healthy only after the rebind is persisted by the caller.
                HealthSignal::NotSampled
            }
        }
    };
    let controller =
        sample_loopback_listener_owner(&record.controller_host, record.controller_port, record.pid);
    let adapter = match native_adapter_instance_id(&record.adapter_alias) {
        Ok(None) => HealthSignal::Unhealthy,
        Ok(Some(instance))
            if record
                .adapter_instance_id
                .as_deref()
                .is_some_and(|recorded| instance.eq_ignore_ascii_case(recorded)) =>
        {
            HealthSignal::Healthy
        }
        Ok(Some(_)) | Err(_) => HealthSignal::Unknown,
    };
    let observation = RuntimeObservation {
        engine,
        upstream,
        controller,
        adapter,
    };
    #[cfg(feature = "acceptance-fault-injection")]
    {
        let mut observation = observation;
        match super::acceptance::active_fault() {
            Ok(Some(super::acceptance::AcceptanceFault::RuntimeUpstreamUnavailable)) => {
                observation.upstream = HealthSignal::Unhealthy;
            }
            Ok(Some(super::acceptance::AcceptanceFault::RuntimeControllerUnavailable)) => {
                observation.controller = HealthSignal::Unhealthy;
            }
            Ok(_) => {}
            Err(_) => return unknown_observation(true),
        }
        observation
    }
    #[cfg(not(feature = "acceptance-fault-injection"))]
    {
        observation
    }
}

fn unknown_observation(include_slow_signals: bool) -> RuntimeObservation {
    if include_slow_signals {
        RuntimeObservation {
            engine: HealthSignal::Unknown,
            upstream: HealthSignal::Unknown,
            controller: HealthSignal::Unknown,
            adapter: HealthSignal::Unknown,
        }
    } else {
        RuntimeObservation::engine_only(HealthSignal::Unknown)
    }
}
