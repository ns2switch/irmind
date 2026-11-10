#![forbid(unsafe_code)]
mod native;

fn main() -> std::process::ExitCode {
    native::entrypoint(irmind_evtx::decode)
}
