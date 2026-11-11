use super::Partition;
#[cfg(test)]
use super::{AppError, EvidenceHash, GraphRecord, invalid_source, storage};
#[cfg(test)]
use chrono::{DateTime, SecondsFormat, Utc};
#[cfg(test)]
use serde_json::Value;
#[derive(serde::Serialize, serde::Deserialize)]
pub(in crate::parquet_store) struct RecordRow {
    pub(in crate::parquet_store) partition: Partition,
    pub(super) hash: String,
    pub(super) index: u64,
    pub(super) at: String,
    pub(super) event: String,
    pub(super) text: String,
    pub(super) entities: String,
    pub(super) entity_pairs: Vec<(String, String)>,
    pub(super) relations: String,
    #[serde(with = "super::staged_time")]
    pub(super) time: Option<irmind_app::IndexedTime>,
    pub(super) source_offset: Option<u64>,
    pub(super) precise: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::parquet_store) common: Option<super::common::CommonRow>,
    pub(in crate::parquet_store) profile: u8,
    pub(in crate::parquet_store) scope_account: String,
    pub(in crate::parquet_store) scope_region: String,
    pub(in crate::parquet_store) scope_host: String,
}

impl RecordRow {
    #[cfg(test)]
    pub(in crate::parquet_store) fn from_record(
        record: &GraphRecord,
        hash: &EvidenceHash,
    ) -> Result<Self, AppError> {
        let value: Value = serde_json::from_str(&record.text).map_err(storage)?;
        let at = if record.at.is_empty() {
            String::new()
        } else {
            DateTime::parse_from_rfc3339(&record.at)
                .map_err(|_| invalid_source())?
                .with_timezone(&Utc)
                .to_rfc3339_opts(SecondsFormat::Secs, true)
        };
        let account = first_string(
            &value,
            &[
                "/account_id",
                "/recipientAccountId",
                "/userIdentity/accountId",
                "/resource/labels/project_id",
                "/protoPayload/resourceName",
                "/subscriptionId",
            ],
        );
        let region = first_string(
            &value,
            &[
                "/provider",
                "/awsRegion",
                "/resource/labels/location",
                "/region",
                "/location",
            ],
        );
        let region = if region.is_empty()
            && value.get("event_id").is_some()
            && value
                .get("principal")
                .and_then(Value::as_str)
                .is_some_and(|principal| principal.starts_with("arn:aws:"))
        {
            "aws"
        } else {
            region
        };
        let relations = record
            .relations
            .iter()
            .map(|relation| {
                [
                    relation.from_kind.as_str(),
                    relation.from_value.as_str(),
                    relation.relation.as_str(),
                    relation.to_kind.as_str(),
                    relation.to_value.as_str(),
                ]
            })
            .collect::<Vec<_>>();
        Ok(Self {
            partition: legacy_partition(&at, account, region),
            hash: hash.as_str().into(),
            index: u64::try_from(record.index).map_err(storage)?,
            at,
            event: record.event.clone(),
            text: record.text.clone(),
            entities: serde_json::to_string(&record.entities).map_err(storage)?,
            entity_pairs: record.entities.clone(),
            relations: serde_json::to_string(&relations).map_err(storage)?,
            time: None,
            source_offset: None,
            precise: false,
            common: None,
            profile: 0,
            scope_account: account.into(),
            scope_region: region.into(),
            scope_host: String::new(),
        })
    }

    pub(in crate::parquet_store) fn sort_key(&self) -> irmind_domain::StableRecordKey<'static> {
        irmind_domain::StableRecordKey {
            instant: self.time.map(irmind_app::IndexedTime::instant),
            source: "",
            source_hash: "",
            source_offset: self.source_offset,
            record_index: self.index,
        }
    }

    pub(in crate::parquet_store) fn estimated_bytes(&self) -> usize {
        self.common
            .as_ref()
            .map_or(0, super::common::CommonRow::estimated_bytes)
            + self.text.len()
            + self.entities.len()
            + self.relations.len()
            + self.event.len()
            + self.at.len()
            + self.hash.len()
            + self.entities.len().saturating_mul(self.entity_pairs.len())
            + self
                .entity_pairs
                .iter()
                .map(|(kind, value)| kind.len() + value.len())
                .sum::<usize>()
    }
}

#[cfg(test)]
pub(super) fn first_string<'a>(value: &'a Value, pointers: &[&str]) -> &'a str {
    pointers
        .iter()
        .find_map(|pointer| value.pointer(pointer).and_then(Value::as_str))
        .unwrap_or("")
}

#[cfg(test)]
pub(in crate::parquet_store) fn safe_partition(value: &str) -> String {
    if value.is_empty() {
        return "unknown".into();
    }
    if value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return value.to_ascii_lowercase();
    }
    format!(
        "h{}",
        &irmind_app::hex(&irmind_app::sha256(value.as_bytes()))[..16]
    )
}

#[cfg(test)]
pub(in crate::parquet_store) fn raw_host(value: &Value) -> &str {
    first_string(
        value,
        &[
            "/host",
            "/hostname",
            "/hostName",
            "/event/host",
            "/Computer",
            "/Host",
            "/host/name",
            "/device/hostname",
            "/attributes/host/name",
            "/attributes/device/hostname",
        ],
    )
}

#[cfg(test)]
fn legacy_partition(at: &str, account: &str, region: &str) -> Partition {
    Partition {
        date: if at.is_empty() {
            "unknown".into()
        } else {
            at[..10].into()
        },
        account: safe_partition(account),
        region: safe_partition(region),
        scope: None,
        segment: 0,
        mapping_route: None,
    }
}
