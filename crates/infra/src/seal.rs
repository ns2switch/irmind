use crate::*;

pub(crate) const MAX_EXPORT_BYTES: usize = 128 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
pub(crate) struct ExportBundle {
    version: u32,
    case_id: String,
    title: String,
    #[serde(default = "default_export_severity")]
    severity: String,
    scope: String,
    audit: Vec<SignedEntry>,
    seal: CaseSeal,
    evidence: std::collections::BTreeMap<String, String>,
}

fn default_export_severity() -> String {
    "medium".into()
}

mod artifact_frames;
mod export;
mod export_v4;
mod frames;
mod local;
mod parquet_frame;
mod verify_v4;
pub use export::{LocalExportVerifier, verify_export, verify_export_expected};
