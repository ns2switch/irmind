use super::Decoded;
use irmind_app::AppError;
#[derive(Default)]
pub(super) struct Groups(crate::audit::source::Groups);
impl Groups {
    pub(super) fn push(
        &mut self,
        raw: &str,
        index: u64,
        offset: u64,
    ) -> Result<Vec<Decoded>, AppError> {
        let result = self.0.push(raw, index, offset);
        if result.is_err() {
            self.0.invalidate_open();
        }
        result.map(convert)
    }
    pub(super) fn invalidate_open(&mut self) {
        self.0.invalidate_open();
    }
    pub(super) fn finish(&mut self) -> Result<Vec<Decoded>, AppError> {
        self.0.finish().map(convert)
    }
}
fn convert(events: Vec<crate::audit::source::DecodedAudit>) -> Vec<Decoded> {
    events
        .into_iter()
        .map(|r| Decoded {
            fields: r.fields,
            timestamp: r.timestamp,
            dataset: "auditd".into(),
            partial: r.partial,
            members: r.members,
            offset: None,
            raw: None,
        })
        .collect()
}
