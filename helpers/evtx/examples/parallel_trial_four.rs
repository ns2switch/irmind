#![forbid(unsafe_code)]
//! Benchmark helper with an explicit four-slot cap.
mod trial_support;

fn main() -> std::process::ExitCode {
    trial_support::run(4)
}
