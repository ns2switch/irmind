#![forbid(unsafe_code)]
//! Benchmark helper only. Release packaging continues to use irmind-evtx.
mod trial_support;

fn main() -> std::process::ExitCode {
    trial_support::run(usize::MAX)
}
