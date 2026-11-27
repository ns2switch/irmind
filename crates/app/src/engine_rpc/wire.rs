use serde::Deserialize;
use serde_json::Value;
use std::io::{self, Read, Write};
use uuid::Uuid;

pub(super) const MAGIC: &[u8] = b"IRMIND-RPC-V1\0";
const MAX_FRAME: usize = 64 * 1024;
const MAX_DEPTH: usize = 16;
const MAX_NODES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Fault {
    Version,
    Invalid,
    Scope,
    Busy,
    Expired,
    Resync,
    Cancelled,
}

impl Fault {
    pub(super) const fn wire(self) -> (u8, &'static str) {
        match self {
            Self::Version => (1, "Unsupported engine protocol version"),
            Self::Invalid => (2, "Invalid engine request"),
            Self::Scope => (3, "Case or operation not admitted"),
            Self::Busy => (4, "The case is busy"),
            Self::Expired => (5, "Engine session expired"),
            Self::Resync => (6, "Refresh case status and subscribe again"),
            Self::Cancelled => (7, "Operation cancelled"),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub(super) id: u32,
    pub(super) method: Method,
    pub(super) params: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Method {
    Hello,
    OpenCase,
    CaseStatus,
    Subscribe,
    StartTurn,
    Cancel,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Hello {
    pub(super) client: String,
    pub(super) version: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Case {
    pub(super) case_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Subscribe {
    pub(super) case_id: String,
    pub(super) after: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StartTurn {
    pub(super) case_id: String,
    pub(super) text: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Cancel {
    pub(super) case_id: String,
    pub(super) operation: String,
}

pub(super) fn canonical_uuid(text: &str) -> bool {
    Uuid::parse_str(text).is_ok_and(|id| id.hyphenated().to_string() == text)
}

pub(super) fn read_magic(reader: &mut impl Read) -> io::Result<()> {
    let mut magic = [0; MAGIC.len()];
    reader.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn request(reader: &mut impl Read) -> io::Result<Option<Request>> {
    let mut length = [0; 4];
    loop {
        match reader.read(&mut length[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) => return Err(error),
        }
    }
    reader.read_exact(&mut length[1..])?;
    let length = u32::from_be_bytes(length) as usize;
    if !(1..=MAX_FRAME).contains(&length) {
        return Err(invalid());
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    let mut body: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    // Re-encoding also rejects duplicate keys, nonminimal escaping, numeric
    // spellings that do not round trip, whitespace, BOM, and reordered keys.
    if canonical(&mut body)? != bytes {
        return Err(invalid());
    }
    serde_json::from_value(body)
        .map(Some)
        .map_err(|_| invalid())
}

pub(super) fn params<T: serde::de::DeserializeOwned>(body: Value) -> Result<T, Fault> {
    serde_json::from_value(body).map_err(|_| Fault::Invalid)
}

pub(super) fn frame(mut value: Value) -> io::Result<Vec<u8>> {
    let bytes = canonical(&mut value)?;
    if bytes.len() > MAX_FRAME {
        return Err(invalid());
    }
    let length = u32::try_from(bytes.len()).map_err(|_| invalid())?;
    let mut framed = Vec::with_capacity(4 + bytes.len());
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(&bytes);
    Ok(framed)
}

fn canonical(value: &mut Value) -> io::Result<Vec<u8>> {
    let mut nodes = 0;
    sort(value, 1, &mut nodes)?;
    serde_json::to_vec(value).map_err(|_| invalid())
}

fn sort(value: &mut Value, depth: usize, nodes: &mut usize) -> io::Result<()> {
    *nodes += 1;
    if depth > MAX_DEPTH || *nodes > MAX_NODES {
        return Err(invalid());
    }
    match value {
        Value::Array(array) => {
            for item in array {
                sort(item, depth + 1, nodes)?;
            }
        }
        Value::Object(object) => {
            object.sort_keys();
            for item in object.values_mut() {
                sort(item, depth + 1, nodes)?;
            }
        }
        Value::Number(number) if number.as_u64().is_none() => return Err(invalid()),
        _ => (),
    }
    Ok(())
}

pub(super) fn flush(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    writer.write_all(bytes)?;
    writer.flush()
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid IRMind RPC frame")
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hello_has_independent_canonical_frame_bytes() {
        let payload =
            br#"{"id":1,"method":"hello","params":{"client":"synthetic-gui","version":1}}"#;
        let frame =
            frame(json!({"params":{"version":1,"client":"synthetic-gui"},"method":"hello","id":1}))
                .expect("hello frame");
        assert_eq!(
            frame[..4],
            u32::try_from(payload.len()).expect("length").to_be_bytes()
        );
        assert_eq!(&frame[4..], payload);
        assert!(request(&mut frame.as_slice()).expect("decode").is_some());
    }

    #[test]
    fn rejects_noncanonical_unbounded_and_non_api_messages() {
        let payloads = [
            r#"{"id":1,"id":2,"method":"hello","params":{}}"#,
            r#"{"id":1, "method":"hello","params":{}}"#,
            r#"{"params":{},"method":"hello","id":1}"#,
            r#"{"id":1,"method":"hello","params":{"version":-1}}"#,
            r#"{"id":1,"method":"hello","params":{"version":1.0}}"#,
            r#"{"id":1,"method":"approve","params":{}}"#,
            r#"{"id":1,"method":"request_approval_prompt","params":{}}"#,
            r#"{"id":1,"method":"approval_status","params":{}}"#,
            r#"{"id":1,"method":"hello","params":{},"token":0}"#,
        ];
        for payload in payloads {
            let mut framed = u32::try_from(payload.len())
                .expect("length")
                .to_be_bytes()
                .to_vec();
            framed.extend_from_slice(payload.as_bytes());
            assert!(request(&mut framed.as_slice()).is_err(), "{payload}");
        }
        for mut bad in [
            &0u32.to_be_bytes()[..],
            &65_537u32.to_be_bytes()[..],
            &[0, 0, 0, 8, b'{'],
        ] {
            assert!(request(&mut bad).is_err());
        }
        let deep = (0..MAX_DEPTH).fold(Value::Null, |child, _| Value::Array(vec![child]));
        assert!(frame(deep).is_err());
        assert!(frame(Value::Array(vec![Value::Null; MAX_NODES])).is_err());
        assert!(read_magic(&mut &b"IRMIND-RPC-V2\0"[..]).is_err());
    }
}
