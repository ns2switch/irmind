use super::{AppError, Extraction, error};
use crate::{config::Format, mapping::Original};
use irmind_app::{
    IndexedGraphRecord, PartitionProfile, SourceMapper,
    source_mapping::{
        MappingDiagnostic, MappingError, MappingManifest, MappingOutput, MappingPartition,
        SourceRecordV1, SourceValue,
    },
};
use std::collections::BTreeMap;
impl SourceMapper for Extraction {
    fn manifest(&self) -> &MappingManifest {
        &self.manifest
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        if !self
            .manifest
            .selectors()
            .iter()
            .any(|selector| selector.matches(source))
        {
            return Err(MappingError::UnsupportedSourceValue);
        }
        let fields = values(&self.parser, source.fields())
            .map_err(|_| MappingError::UnsupportedSourceValue)?;
        let raw = source
            .annotations()
            .raw()
            .ok_or(MappingError::UnsupportedSourceValue)?;
        let original = if matches!(
            self.parser.definition.input.format,
            Format::Json | Format::Ndjson
        ) {
            Original::Json(
                serde_json::from_str(raw).map_err(|_| MappingError::UnsupportedSourceValue)?,
            )
        } else {
            Original::Text(raw)
        };
        let graph = self
            .parser
            .map_record(
                usize::try_from(source.origin().record())
                    .map_err(|_| MappingError::UnsupportedSourceValue)?,
                &fields,
                original,
            )
            .map_err(|_| MappingError::UnsupportedSourceValue)?;
        let host = self
            .parser
            .definition
            .mapping
            .get("host")
            .and_then(|p| fields.get(p))
            .map_or("", String::as_str);
        MappingOutput::try_new(
            source,
            IndexedGraphRecord {
                record: graph,
                time: source.timestamp(),
                source_offset: source.origin().offset(),
            },
            MappingOutput::unclassified_common(source)?,
            MappingPartition::try_new(
                if self.parser.definition.mapping.contains_key("host") {
                    PartitionProfile::EndpointHost
                } else {
                    PartitionProfile::Unpartitioned
                },
                "",
                "",
                host,
            )?,
            vec![MappingDiagnostic::Unclassified],
        )
    }
}
pub(super) fn values(
    parser: &crate::DeclarativeParser,
    source: &SourceValue,
) -> Result<BTreeMap<String, String>, AppError> {
    let mut values = BTreeMap::new();
    for path in parser.definition.mapping.values() {
        if let Some(text) = read_value(parser, source, path)? {
            values.insert(path.clone(), text);
        }
    }
    Ok(values)
}
pub(super) fn read_value(
    parser: &crate::DeclarativeParser,
    source: &SourceValue,
    path: &str,
) -> Result<Option<String>, AppError> {
    let value = if matches!(
        parser.definition.input.format,
        Format::Json | Format::Ndjson
    ) {
        pointer(source, path)
    } else {
        source.field(path)
    };
    let text = match value {
        None | Some(SourceValue::Null) => return Ok(None),
        Some(SourceValue::Text(text)) => text.clone(),
        Some(value) => irmind_app::source_mapping::json::render_source_fields(value)
            .map_err(|_| error("invalid mapped value"))?,
    };
    if text.len() > 4096 {
        return Err(error("mapped value exceeds 4096 bytes"));
    }
    Ok(Some(text))
}
fn pointer<'a>(mut value: &'a SourceValue, path: &str) -> Option<&'a SourceValue> {
    for part in path.strip_prefix('/')?.split('/') {
        let key = part.replace("~1", "/").replace("~0", "~");
        value = match value {
            SourceValue::Object(fields) => fields.get(&key)?,
            SourceValue::Array(items) => items.get(key.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(value)
}
