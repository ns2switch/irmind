#![forbid(unsafe_code)]
pub(super) fn helper_path() -> std::path::PathBuf {
    std::env::var_os("IRMIND_EVTX_HELPER_TEST").map_or_else(
        || std::path::PathBuf::from(env!("CARGO_BIN_EXE_irmind-evtx")),
        std::path::PathBuf::from,
    )
}
