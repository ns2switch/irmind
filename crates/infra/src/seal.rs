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

include!("seal/local.rs");
include!("seal/export.rs");
