use super::{SourceRecordV1, SourceValue};

fn bytes(value: &[u8], feed: &mut dyn FnMut(&[u8])) {
    feed(&(value.len() as u64).to_be_bytes());
    feed(value);
}
fn optional(value: Option<u64>, feed: &mut dyn FnMut(&[u8])) {
    feed(&[u8::from(value.is_some())]);
    if let Some(value) = value {
        feed(&value.to_be_bytes());
    }
}

pub(super) fn record(source: &SourceRecordV1, feed: &mut dyn FnMut(&[u8])) {
    feed(b"irmind-source-record-v1\0");
    bytes(source.origin.source().as_str().as_bytes(), feed);
    feed(&source.origin.record().to_be_bytes());
    optional(source.origin.offset(), feed);
    bytes(source.origin.parser().as_bytes(), feed);
    bytes(source.origin.parser_version().as_bytes(), feed);
    bytes(source.source.reference().as_bytes(), feed);
    feed(&[
        source.source.kind_code(),
        u8::from(source.source.acquisition().is_some()),
    ]);
    if let Some(acquisition) = source.source.acquisition() {
        bytes(acquisition.as_str().as_bytes(), feed);
    }
    feed(&[u8::from(source.timestamp.is_some())]);
    if let Some(time) = source.timestamp {
        feed(&time.instant().unix_micros().to_be_bytes());
        feed(&time.instant().submicro_nanos().to_be_bytes());
        feed(&[time.precision().code(), u8::from(time.inferred())]);
    }
    bytes(source.format.id().as_bytes(), feed);
    bytes(source.format.version().as_bytes(), feed);
    feed(&(source.format.discriminators().len() as u64).to_be_bytes());
    for (key, field) in source.format.discriminators() {
        feed(&[key.code()]);
        bytes(field.as_bytes(), feed);
    }
    value(&source.fields, feed);
    feed(&[u8::from(source.annotations.partial)]);
    feed(&(source.annotations.members.len() as u64).to_be_bytes());
    for member in &source.annotations.members {
        feed(&member.ordinal.to_be_bytes());
        optional(member.offset, feed);
    }
    feed(&[u8::from(source.annotations.raw.is_some())]);
    if let Some(raw) = &source.annotations.raw {
        bytes(raw.as_bytes(), feed);
    }
    if let Some(cluster) = &source.cluster {
        feed(b"irmind-source-record-cluster-v1\0");
        bytes(cluster.provider().as_str().as_bytes(), feed);
        bytes(cluster.id().as_bytes(), feed);
    }
}

fn value(input: &SourceValue, feed: &mut dyn FnMut(&[u8])) {
    match input {
        SourceValue::Null => feed(&[0]),
        SourceValue::Boolean(b) => feed(&[1, u8::from(*b)]),
        SourceValue::Number(n) => {
            feed(&[2]);
            bytes(n.as_str().as_bytes(), feed);
        }
        SourceValue::Text(s) => {
            feed(&[3]);
            bytes(s.as_bytes(), feed);
        }
        SourceValue::Bytes(b) => {
            feed(&[4]);
            bytes(b, feed);
        }
        SourceValue::Array(values) => {
            feed(&[5]);
            feed(&(values.len() as u64).to_be_bytes());
            for item in values {
                value(item, feed);
            }
        }
        SourceValue::Object(fields) => {
            feed(&[6]);
            feed(&(fields.len() as u64).to_be_bytes());
            for (key, item) in fields {
                bytes(key.as_bytes(), feed);
                value(item, feed);
            }
        }
    }
}
