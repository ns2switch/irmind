#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]
use irmind_app::{SourceDecoder, SourceMapper};
use irmind_mod_mapping_evtx::{PowerShellMapping, SecurityMapping, SysmonMapping, SystemMapping};
use std::{path::PathBuf, sync::Arc};
fn helper() -> PathBuf {
    std::env::var_os("IRMIND_EVTX_HELPER_TEST").map_or_else(
        || {
            std::env::current_exe()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join(if cfg!(windows) {
                    "irmind-evtx.exe"
                } else {
                    "irmind-evtx"
                })
        },
        PathBuf::from,
    )
}
#[test]
fn contained_decoder_passes_the_seekable_mapping_contract_for_all_channels() {
    let root = tempfile::tempdir().unwrap();
    let parser = irmind_mod_parser_evtx::EvtxParser::new(&helper(), root.path());
    if let Some(reason) = parser.unavailable_reason() {
        assert!(
            std::env::var_os("GITHUB_ACTIONS").is_none(),
            "native mapping contract requires verified isolation: {reason}"
        );
        eprintln!("native EVTX mapping unavailable: {reason}");
        return;
    }
    let decoder: Arc<dyn SourceDecoder> = Arc::new(parser);
    let mut mappers: Vec<Arc<dyn SourceMapper>> = vec![
        Arc::new(SystemMapping::new().unwrap()),
        Arc::new(PowerShellMapping::new().unwrap()),
        Arc::new(SysmonMapping::new().unwrap()),
    ];
    for &id in SecurityMapping::EVENT_IDS {
        mappers.push(Arc::new(SecurityMapping::new(id).unwrap()));
    }
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testkit/fixtures/mapping-evtx/source");
    for (name, count) in [
        ("security", 17),
        ("system", 1),
        ("powershell", 2),
        ("sysmon", 5),
    ] {
        irmind_testkit::run_source_file_mapping_contract(
            Arc::clone(&decoder),
            mappers.clone(),
            &format!("{name}.evtx"),
            &fixture.join(format!("{name}.evtx")),
            count,
        )
        .unwrap();
    }
}
