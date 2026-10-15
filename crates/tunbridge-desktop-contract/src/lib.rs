use serde::Serialize;

pub mod adapter;

pub const COMMAND_SURFACE_SCHEMA_VERSION: u16 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformErrorCode {
    NotReady,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformError {
    pub code: PlatformErrorCode,
    pub safe_message: &'static str,
    pub retryable: bool,
    pub platform: &'static str,
    pub capability: &'static str,
}

impl PlatformError {
    pub const fn not_ready(platform: &'static str, capability: &'static str) -> Self {
        Self {
            code: PlatformErrorCode::NotReady,
            safe_message: "This capability is not ready on the current platform.",
            retryable: false,
            platform,
            capability,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandSpec {
    pub name: &'static str,
    pub input_field: Option<&'static str>,
}

pub const COMMAND_SURFACE: [CommandSpec; 30] = [
    CommandSpec {
        name: "get_status",
        input_field: None,
    },
    CommandSpec {
        name: "take_pending_tray_navigation",
        input_field: None,
    },
    CommandSpec {
        name: "get_traffic_snapshot",
        input_field: None,
    },
    CommandSpec {
        name: "get_connections_page",
        input_field: Some("input"),
    },
    CommandSpec {
        name: "get_mihomo_logs_page",
        input_field: Some("input"),
    },
    CommandSpec {
        name: "close_connection",
        input_field: Some("input"),
    },
    CommandSpec {
        name: "close_all_connections",
        input_field: None,
    },
    CommandSpec {
        name: "test_website",
        input_field: Some("input"),
    },
    CommandSpec {
        name: "get_ip_information",
        input_field: None,
    },
    CommandSpec {
        name: "get_system_information",
        input_field: None,
    },
    CommandSpec {
        name: "set_auto_launch",
        input_field: Some("enabled"),
    },
    CommandSpec {
        name: "get_app_update_information",
        input_field: None,
    },
    CommandSpec {
        name: "open_app_releases_page",
        input_field: None,
    },
    CommandSpec {
        name: "get_core_update_information",
        input_field: None,
    },
    CommandSpec {
        name: "install_core_update",
        input_field: None,
    },
    CommandSpec {
        name: "discover_upstreams",
        input_field: None,
    },
    CommandSpec {
        name: "test_upstream",
        input_field: Some("input"),
    },
    CommandSpec {
        name: "list_profiles",
        input_field: None,
    },
    CommandSpec {
        name: "create_profile",
        input_field: Some("input"),
    },
    CommandSpec {
        name: "update_profile",
        input_field: Some("input"),
    },
    CommandSpec {
        name: "delete_profile",
        input_field: Some("input"),
    },
    CommandSpec {
        name: "test_saved_profile",
        input_field: Some("input"),
    },
    CommandSpec {
        name: "start_saved_profile",
        input_field: Some("input"),
    },
    CommandSpec {
        name: "get_active_profile_id",
        input_field: None,
    },
    CommandSpec {
        name: "stop_tunnel",
        input_field: None,
    },
    CommandSpec {
        name: "recover_tunnel",
        input_field: None,
    },
    CommandSpec {
        name: "install_product",
        input_field: None,
    },
    CommandSpec {
        name: "uninstall_product",
        input_field: None,
    },
    CommandSpec {
        name: "confirm_exit",
        input_field: Some("input"),
    },
    CommandSpec {
        name: "get_tunnel_events",
        input_field: None,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn command_surface_is_unique_and_stable() {
        let names: BTreeSet<_> = COMMAND_SURFACE.iter().map(|command| command.name).collect();
        assert_eq!(names.len(), COMMAND_SURFACE.len());
        assert_eq!(COMMAND_SURFACE_SCHEMA_VERSION, 3);
        assert_eq!(COMMAND_SURFACE[0].name, "get_status");
        assert_eq!(COMMAND_SURFACE[27].name, "uninstall_product");

        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/command-surface-v3.json")).unwrap();
        assert_eq!(serde_json::to_value(COMMAND_SURFACE).unwrap(), fixture);
    }

    #[test]
    fn not_ready_error_has_safe_stable_schema() {
        let serialized =
            serde_json::to_value(PlatformError::not_ready("macos", "service_lifecycle")).unwrap();
        assert_eq!(
            serialized,
            serde_json::json!({
                "code": "not_ready",
                "safeMessage": "This capability is not ready on the current platform.",
                "retryable": false,
                "platform": "macos",
                "capability": "service_lifecycle"
            })
        );
    }
}
