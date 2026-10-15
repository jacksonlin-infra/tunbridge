#[cfg(windows)]
fn main() {
    use tunbridge_setup::windows::{execute, SetupReport, SetupVerb};

    fn emit_report(report: &SetupReport) {
        let json = serde_json::to_string(report).unwrap();
        println!("{json}");
        // ShellExecute cannot inherit a redirected stdout handle across UAC.
        // Persist only the fixed, redacted report so the desktop can diagnose
        // an elevated transaction without exposing paths or Windows errors.
        let _ = std::fs::write(
            std::env::temp_dir().join("TunBridge-setup-last.json"),
            &json,
        );
    }

    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let verb = match SetupVerb::parse(&arguments) {
        Ok(verb) => verb,
        Err(error) => {
            eprintln!("{}", error.code());
            std::process::exit(2);
        }
    };
    match execute(verb) {
        Ok(upgraded) => emit_report(&SetupReport::success(verb, upgraded)),
        Err(error) => {
            emit_report(&SetupReport::failure(verb, &error));
            std::process::exit(1);
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("tunbridge-setup is only supported on Windows");
    std::process::exit(1);
}
