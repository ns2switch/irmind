//! Classification tables are release-bound by the native build manifest.
use irmind_app::source_mapping::{MappingError, SourceRecordV1};
use irmind_domain::{EventHeaderV1, EventOutcome};
use irmind_mapping_tables::TableMapping;
struct Header {
    key: &'static str,
    base: TableMapping,
    outcome: Option<TableMapping>,
}
pub(super) struct Headers(Vec<Header>);
impl Headers {
    pub(super) fn new(parser: &str) -> Result<Self, MappingError> {
        let short = parser
            .strip_prefix("parser-")
            .ok_or(MappingError::InvalidManifest)?;
        DATA.iter()
            .filter(|(p, ..)| *p == short)
            .map(|(_, key, base, outcome)| {
                Ok(Header {
                    key,
                    base: compile(base)?,
                    outcome: outcome.map(compile).transpose()?,
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }
    pub(super) fn get(
        &self,
        source: &SourceRecordV1,
        key: &str,
    ) -> Result<EventHeaderV1, MappingError> {
        let Some(table) = self.0.iter().find(|t| t.key == key) else {
            return Ok(EventHeaderV1::default());
        };
        let mut header = table.base.event_header(source)?;
        if let Some(table) = &table.outcome {
            let explicit = table.event_header(source)?;
            if explicit.categories().bits() != 0 {
                header = explicit;
            }
        }
        // TSV preserves strings and declared source types. Convert status only here;
        // no normalized record or forged SourceRecord is introduced for a table.
        if key == "zeek-tsv-http" || key == "zeek-tsv-dns" {
            let field = if key.ends_with("http") {
                "status_code"
            } else {
                "rcode"
            };
            let code = source
                .fields()
                .field("columns")
                .and_then(|v| v.field(field))
                .and_then(irmind_app::source_mapping::SourceValue::as_text)
                .and_then(|v| v.parse::<u16>().ok());
            let outcome = match (key.ends_with("http"), code) {
                (true, Some(200..=399)) | (false, Some(0)) => EventOutcome::Success,
                (true, Some(400..=599)) | (false, Some(1..=u16::MAX)) => EventOutcome::Failure,
                _ => header.outcome(),
            };
            header =
                EventHeaderV1::new(header.categories(), header.types(), outcome, header.kind());
        }
        Ok(header)
    }
}
fn compile(text: &str) -> Result<TableMapping, MappingError> {
    let reviewed = TableMapping::review(text)?;
    TableMapping::bundled(text, reviewed.identity().implementation())
}
type Definition = (
    &'static str,
    &'static str,
    &'static str,
    Option<&'static str>,
);
const DATA: &[Definition] = &[
    (
        "zeek",
        "zeek-json-conn",
        include_str!("tables/zeek-json-conn.toml"),
        Some(include_str!("tables/zeek-json-conn-outcome.toml")),
    ),
    (
        "zeek",
        "zeek-json-dns",
        include_str!("tables/zeek-json-dns.toml"),
        Some(include_str!("tables/zeek-json-dns-outcome.toml")),
    ),
    (
        "zeek",
        "zeek-json-http",
        include_str!("tables/zeek-json-http.toml"),
        Some(include_str!("tables/zeek-json-http-outcome.toml")),
    ),
    (
        "zeek",
        "zeek-json-ssl",
        include_str!("tables/zeek-json-ssl.toml"),
        Some(include_str!("tables/zeek-json-ssl-outcome.toml")),
    ),
    (
        "zeek",
        "zeek-json-files",
        include_str!("tables/zeek-json-files.toml"),
        None,
    ),
    (
        "zeek",
        "zeek-json-x509",
        include_str!("tables/zeek-json-x509.toml"),
        None,
    ),
    (
        "zeek",
        "zeek-json-notice",
        include_str!("tables/zeek-json-notice.toml"),
        None,
    ),
    (
        "zeek",
        "zeek-json-weird",
        include_str!("tables/zeek-json-weird.toml"),
        None,
    ),
    (
        "zeek",
        "zeek-tsv-conn",
        include_str!("tables/zeek-tsv-conn.toml"),
        Some(include_str!("tables/zeek-tsv-conn-outcome.toml")),
    ),
    (
        "zeek",
        "zeek-tsv-dns",
        include_str!("tables/zeek-tsv-dns.toml"),
        Some(include_str!("tables/zeek-tsv-dns-outcome.toml")),
    ),
    (
        "zeek",
        "zeek-tsv-http",
        include_str!("tables/zeek-tsv-http.toml"),
        None,
    ),
    (
        "zeek",
        "zeek-tsv-ssl",
        include_str!("tables/zeek-tsv-ssl.toml"),
        Some(include_str!("tables/zeek-tsv-ssl-outcome.toml")),
    ),
    (
        "zeek",
        "zeek-tsv-files",
        include_str!("tables/zeek-tsv-files.toml"),
        None,
    ),
    (
        "zeek",
        "zeek-tsv-x509",
        include_str!("tables/zeek-tsv-x509.toml"),
        None,
    ),
    (
        "zeek",
        "zeek-tsv-notice",
        include_str!("tables/zeek-tsv-notice.toml"),
        None,
    ),
    (
        "zeek",
        "zeek-tsv-weird",
        include_str!("tables/zeek-tsv-weird.toml"),
        None,
    ),
    (
        "suricata",
        "suricata-json-flow",
        include_str!("tables/suricata-json-flow.toml"),
        None,
    ),
    (
        "suricata",
        "suricata-json-dns",
        include_str!("tables/suricata-json-dns.toml"),
        Some(include_str!("tables/suricata-json-dns-outcome.toml")),
    ),
    (
        "suricata",
        "suricata-json-http",
        include_str!("tables/suricata-json-http.toml"),
        Some(include_str!("tables/suricata-json-http-outcome.toml")),
    ),
    (
        "suricata",
        "suricata-json-tls",
        include_str!("tables/suricata-json-tls.toml"),
        None,
    ),
    (
        "suricata",
        "suricata-json-fileinfo",
        include_str!("tables/suricata-json-fileinfo.toml"),
        None,
    ),
    (
        "suricata",
        "suricata-json-alert",
        include_str!("tables/suricata-json-alert.toml"),
        None,
    ),
    (
        "suricata",
        "suricata-json-anomaly",
        include_str!("tables/suricata-json-anomaly.toml"),
        None,
    ),
];
