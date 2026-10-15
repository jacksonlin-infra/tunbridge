mod run;

use clap::Parser;

fn main() {
    let cli = run::Cli::parse();
    std::process::exit(run::run(cli));
}
