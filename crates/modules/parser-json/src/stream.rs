use super::{AppError, GraphRecord, Tainted, normalize_record, parse_record, sha256};
use irmind_app::CancellationToken;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::error::Category;
use serde_json::{Map, Value};

const MAX_FIELDS: usize = 1024;
const MAX_DEPTH: usize = 64;

struct RecordSink<'a> {
    source: &'a str,
    evidence_hash: [u8; 32],
    cancel: &'a CancellationToken,
    emit: &'a mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    count: usize,
    max_records: usize,
    failure: Option<AppError>,
}

impl RecordSink<'_> {
    fn accept(&mut self, value: Value) -> Result<(), AppError> {
        validate_shape(&value)?;
        if self.count >= self.max_records {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::TooManyJSONRecords,
            )));
        }
        if self.count.is_multiple_of(256) && self.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let mut value = normalize_record(value);
        // Preserve the historical lexical traversal, including extraction caps.
        value.sort_all_objects();
        let record = parse_record(self.source, self.evidence_hash, self.count, &value)?;
        let result = (self.emit)(record);
        result?;
        self.count += 1;
        Ok(())
    }

    fn accept_json<E: de::Error>(&mut self, value: Value) -> Result<(), E> {
        if let Err(error) = self.accept(value) {
            self.failure = Some(error);
            return Err(E::custom("JSON record rejected"));
        }
        Ok(())
    }
}

fn validate_shape(value: &Value) -> Result<(), AppError> {
    fn walk(value: &Value, depth: usize, fields: &mut usize) -> bool {
        if depth > MAX_DEPTH {
            return false;
        }
        match value {
            Value::Object(object) => {
                *fields = fields.saturating_add(object.len());
                *fields <= MAX_FIELDS && object.values().all(|item| walk(item, depth + 1, fields))
            }
            Value::Array(array) => array.iter().all(|item| walk(item, depth + 1, fields)),
            _ => true,
        }
    }
    if !walk(value, 0, &mut 0) {
        return Err(AppError::Policy(
            "JSON record exceeds field or depth limit".into(),
        ));
    }
    Ok(())
}

struct Root<'a, 'b>(&'a mut RecordSink<'b>);

impl<'de> DeserializeSeed<'de> for Root<'_, '_> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(RootVisitor(self.0))
    }
}

struct RootVisitor<'a, 'b>(&'a mut RecordSink<'b>);

impl<'de> Visitor<'de> for RootVisitor<'_, '_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON object or array")
    }

    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<(), S::Error> {
        while let Some(value) = seq.next_element::<Value>()? {
            self.0.accept_json(value)?;
        }
        Ok(())
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
        let mut object = Map::new();
        let mut wrapped = false;
        while let Some(key) = map.next_key::<String>()? {
            if matches!(key.as_str(), "Records" | "records" | "events") {
                if wrapped {
                    return Err(de::Error::custom("multiple JSON record arrays"));
                }
                map.next_value_seed(RecordArray(self.0))?;
                wrapped = true;
            } else {
                object.insert(key, map.next_value::<Value>()?);
            }
        }
        if !wrapped {
            self.0.accept_json(Value::Object(object))?;
        }
        Ok(())
    }
}

struct RecordArray<'a, 'b>(&'a mut RecordSink<'b>);

impl<'de> DeserializeSeed<'de> for RecordArray<'_, '_> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_seq(RootVisitor(self.0))
    }
}

pub(super) fn parse_each(
    source: &str,
    bytes: &[u8],
    cancel: &CancellationToken,
    emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
) -> Result<usize, AppError> {
    let evidence_hash = sha256(bytes);
    let mut sink = RecordSink {
        source,
        evidence_hash,
        cancel,
        emit,
        count: 0,
        max_records: 100_000,
        failure: None,
    };
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    loop {
        if let Err(error) = Root(&mut sink).deserialize(&mut deserializer) {
            return Err(sink
                .failure
                .take()
                .unwrap_or_else(|| json_error(&error, cancel)));
        }
        match deserializer.end() {
            Ok(()) => break,
            Err(error) if error.classify() == Category::Syntax => {}
            Err(error) => return Err(json_error(&error, cancel)),
        }
    }
    Ok(sink.count)
}

fn json_error(error: &serde_json::Error, cancel: &CancellationToken) -> AppError {
    if cancel.is_cancelled() {
        AppError::Cancelled
    } else {
        AppError::Storage(format!("invalid JSON record: {error}"))
    }
}
