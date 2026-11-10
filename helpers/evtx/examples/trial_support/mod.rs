#[path = "../../src/native.rs"]
mod native;

pub(super) fn run(cap: usize) -> std::process::ExitCode {
    native::entrypoint(|input, output| {
        let workers = if cfg!(any(windows, target_os = "macos")) {
            std::thread::available_parallelism()
                .map_or(1, usize::from)
                .min(cap)
        } else {
            1
        };
        irmind_evtx::decode_with_workers(input, output, workers)
    })
}
