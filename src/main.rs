use std::{env, process::ExitCode};

const HELP: &str = "Usage: cr [OPTIONS]\n\nOptions:\n  -h, --help  Print help";

fn main() -> ExitCode {
    match env::args().nth(1).as_deref() {
        Some("-h" | "--help") | None => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        Some(argument) => {
            eprintln!("error: unexpected argument '{argument}'\n\n{HELP}");
            ExitCode::from(2)
        }
    }
}
