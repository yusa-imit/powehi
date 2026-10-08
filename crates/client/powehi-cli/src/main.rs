//! `powehi` binary: parse arguments, delegate to the library.

use clap::Parser;
use powehi_cli::{cli::Cli, run};

fn main() -> std::process::ExitCode {
    let args = Cli::parse();
    match run(args, dirs::data_dir()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("powehi: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
