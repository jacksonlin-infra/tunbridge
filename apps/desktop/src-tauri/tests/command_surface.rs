use tunbridge_desktop_contract::COMMAND_SURFACE;

#[test]
fn registered_tauri_commands_match_the_shared_contract() {
    let source = include_str!("../src/lib.rs");
    let marker = ".invoke_handler(tauri::generate_handler![";
    let handler = source
        .split_once(marker)
        .expect("Tauri handler marker must exist")
        .1
        .split_once("])")
        .expect("Tauri handler list must terminate")
        .0;
    let registered: Vec<_> = handler
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| line.trim_end_matches(','))
        .collect();
    let contracted: Vec<_> = COMMAND_SURFACE.iter().map(|command| command.name).collect();

    assert_eq!(registered, contracted);
}

#[test]
fn every_contracted_command_is_granted_to_the_main_window() {
    // The app permission manifest enables Tauri's app-command ACL, so a
    // registered command without a granted permission is rejected at runtime.
    let capability: serde_json::Value =
        serde_json::from_str(include_str!("../capabilities/main.json"))
            .expect("main capability must be valid JSON");
    let granted: Vec<_> = capability["permissions"]
        .as_array()
        .expect("main capability must list permissions")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    let mut allowed = Vec::new();
    for block in include_str!("../permissions/status.toml").split("[[permission]]") {
        let field = |name: &str| {
            block
                .lines()
                .find_map(|line| line.trim().strip_prefix(name))
                .map(|value| value.trim().trim_start_matches('=').trim())
        };
        let Some(identifier) = field("identifier") else {
            continue;
        };
        if !granted.contains(&identifier.trim_matches('"')) {
            continue;
        }
        let commands = field("commands.allow").expect("permission must allow commands");
        allowed.extend(
            commands
                .trim_matches(|c| c == '[' || c == ']')
                .split(',')
                .map(|command| command.trim().trim_matches('"').to_owned()),
        );
    }

    for command in COMMAND_SURFACE {
        assert!(
            allowed.iter().any(|name| name == command.name),
            "{} is registered but not granted to the main window",
            command.name
        );
    }
}
