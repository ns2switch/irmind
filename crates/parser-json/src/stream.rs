use super::{AppError, GraphRecord, Tainted, normalize_record, parse_record, sha256};
use irmind_app::CancellationToken;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

struct RecordSink<'a> {
    source: &'a str,
    evidence_hash: [u8; 32],
    cancel: &'a CancellationToken,
    emit: &'a mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    count: usize,
    failure: Option<AppError>,
}

impl RecordSink<'_> {
    fn accept(&mut self, value: Value) -> Result<(), AppError> {
        if self.count >= 100_000 {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::TooManyJSONRecords,
            )));
        }
        if self.count.is_multiple_of(256) && self.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let record = parse_record(
            self.source,
            self.evidence_hash,
            self.count,
            &normalize_record(value),
        )?;
        (self.emit)(record)?;
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
            if key == "Records" || key == "events" {
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
    let mut sink = RecordSink {
        source,
        evidence_hash: sha256(bytes),
        cancel,
        emit,
        count: 0,
        failure: None,
    };
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    loop {
        if let Err(error) = Root(&mut sink).deserialize(&mut deserializer) {
            return Err(sink
                .failure
                .take()
                .unwrap_or_else(|| AppError::Storage(format!("invalid JSON record: {error}"))));
        }
        if deserializer.end().is_ok() {
            break;
        }
    }
    Ok(sink.count)
}
