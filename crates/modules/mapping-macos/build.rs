#![forbid(unsafe_code)]
fn main() -> std::io::Result<()> {
    irmind_build_manifest::emit_native_mapping_manifest_with_sources(
        &[],
        &["crates/mapping-tables"],
    )
}
