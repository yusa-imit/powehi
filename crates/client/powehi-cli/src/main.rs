//! `powehi` binary: parse arguments, delegate to the library.

use clap::Parser;
use powehi_cli::{cli::Cli, run};

fn main() -> std::process::ExitCode {
    #[cfg(unix)]
    if let Err(e) = powehi_cli::hardening::disable_core_dumps() {
        // Refuse to run with secrets in memory if core dumps cannot be disabled.
        eprintln!("powehi: cannot disable core dumps: {e}");
        return std::process::ExitCode::FAILURE;
    }
    let args = Cli::parse();
    match run(args, dirs::data_dir()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("powehi: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
