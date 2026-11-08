#![no_main]
use irmind_mod_mapping_tables::TableMapping;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 65_536 {
        return;
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        if let Ok(manifest) = TableMapping::review(text) {
            let mapper = TableMapping::bundled(text, manifest.identity().implementation()).unwrap();
            assert_eq!(irmind_app::SourceMapper::manifest(&mapper), &manifest);
            let snapshot = manifest.snapshot().unwrap();
            assert_eq!(
                irmind_app::source_mapping::MappingManifest::from_snapshot(&snapshot).unwrap(),
                manifest
            );
        }
    }
});
