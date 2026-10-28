use super::ParserProfile;
use super::{AppError, GraphRecord, Tainted, normalize_record, parse_record, sha256};
use irmind_app::CancellationToken;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::time::Instant;

struct RecordSink<'a> {
    source: &'a str,
    evidence_hash: [u8; 32],
    cancel: &'a CancellationToken,
    emit: &'a mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    count: usize,
    failure: Option<AppError>,
    profile: Option<&'a ParserProfile>,
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
        let started = Instant::now();
        let record = parse_record(
            self.source,
            self.evidence_hash,
            self.count,
            &normalize_record(value),
        )?;
        if let Some(profile) = self.profile {
            profile.extraction(started.elapsed());
        }
        let started = Instant::now();
        let result = (self.emit)(record);
        if let Some(profile) = self.profile {
            profile.emit(started.elapsed());
        }
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
    profile: Option<&ParserProfile>,
) -> Result<usize, AppError> {
    let total_started = Instant::now();
    let hash_started = Instant::now();
    let evidence_hash = sha256(bytes);
    if let Some(profile) = profile {
        profile.hash(hash_started.elapsed());
    }
    let mut sink = RecordSink {
        source,
        evidence_hash,
        cancel,
        emit,
        count: 0,
        failure: None,
        profile,
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
    if let Some(profile) = profile {
        profile.total(total_started.elapsed());
    }
    Ok(sink.count)
}
