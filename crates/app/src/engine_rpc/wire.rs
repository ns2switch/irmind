use secrecy::{SecretString, zeroize::Zeroizing};
use serde::Deserialize;
use serde_json::Value;
use std::io::{self, Read, Write};
use uuid::Uuid;

pub(super) const MAGIC: &[u8] = b"IRMIND-RPC-V1\0";
pub(super) const MAGIC_V2: &[u8] = b"IRMIND-RPC-V2\0";
const MAX_PASSPHRASE_BYTES: usize = 4096;
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
    ReviewInTui,
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
            Self::ReviewInTui => (8, "Review this request in IRMind /approvals"),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub(super) id: u32,
    pub(super) method: Method,
    pub(super) params: Value,
    #[serde(skip)]
    pub(super) submission: Option<Submission>,
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
    ApprovalPrepare,
    ApprovalSubmit,
    ApprovalStatus,
    ApprovalCancel,
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

pub(super) fn read_magic(reader: &mut impl Read, expected: &[u8]) -> io::Result<()> {
    let mut magic = [0; MAGIC.len()];
    reader.read_exact(&mut magic)?;
    if magic != expected {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn request(reader: &mut impl Read, v2: bool) -> io::Result<Option<Request>> {
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
    let mut bytes = Zeroizing::new(vec![0; length]);
    reader.read_exact(&mut bytes)?;
    if let Some(request) = approval_submission(&bytes, v2)? {
        return Ok(Some(request));
    }
    let mut body: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    // Re-encoding also rejects duplicate keys, nonminimal escaping, numeric
    // spellings that do not round trip, whitespace, BOM, and reordered keys.
    if canonical(&mut body)? != bytes.as_slice() {
        return Err(invalid());
    }
    serde_json::from_value(body)
        .map(Some)
        .map_err(|_| invalid())
}

pub(super) struct Submission {
    pub(super) case_id: String,
    pub(super) presentation: String,
    pub(super) view_sha256: String,
    pub(super) credential: Credential,
}

pub(super) enum Credential {
    Passphrase(SecretString),
    WindowsHello,
    TouchId,
}

fn approval_submission(bytes: &[u8], allowed: bool) -> io::Result<Option<Request>> {
    // Inspect the canonical envelope without constructing a JSON value.
    // A malformed secret-bearing frame must also take this path.
    let frame = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    let (id, rest) = frame
        .strip_prefix("{\"id\":")
        .and_then(|frame| frame.split_once(",\"method\":\""))
        .ok_or_else(invalid)?;
    let (method, params) = rest.split_once('"').ok_or_else(invalid)?;
    let params = params.strip_prefix(",\"params\":").ok_or_else(invalid)?;
    if !(1..=32).contains(&method.len())
        || !method
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return Err(invalid());
    }
    if !allowed && method.starts_with("approval_") {
        return Err(invalid());
    }
    if method != "approval_submit" {
        return Ok(None);
    }
    let request_id = id.parse::<u32>().map_err(|_| invalid())?;
    if request_id == 0 || id != request_id.to_string() {
        return Err(invalid());
    }
    let (case_id, rest) = params
        .strip_prefix("{\"case_id\":\"")
        .and_then(|params| params.split_once("\",\"method\":\""))
        .ok_or_else(invalid)?;
    let (method, rest) = rest
        .split_once("\",\"passphrase_hex\":")
        .ok_or_else(invalid)?;
    let (secret, rest) = rest
        .split_once(",\"presentation\":\"")
        .ok_or_else(invalid)?;
    let (presentation, digest) = rest
        .split_once("\",\"view_sha256\":\"")
        .ok_or_else(invalid)?;
    let digest = digest.strip_suffix("\"}}").ok_or_else(invalid)?;
    if !canonical_uuid(case_id)
        || !canonical_uuid(presentation)
        || digest.len() != 64
        || !lowercase_hex(digest)
    {
        return Err(invalid());
    }
    let credential = match (method, secret) {
        ("windows_hello", "null") => Credential::WindowsHello,
        ("touch_id", "null") => Credential::TouchId,
        ("keystore_passphrase", encoded) => Credential::Passphrase(decode_secret(encoded)?),
        _ => return Err(invalid()),
    };
    Ok(Some(Request {
        id: request_id,
        method: Method::ApprovalSubmit,
        params: Value::Null,
        submission: Some(Submission {
            case_id: case_id.to_owned(),
            presentation: presentation.to_owned(),
            view_sha256: digest.to_owned(),
            credential,
        }),
    }))
}

fn decode_secret(encoded: &str) -> io::Result<SecretString> {
    let secret = encoded
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .ok_or_else(invalid)?;
    if secret.is_empty()
        || secret.len() > 2 * MAX_PASSPHRASE_BYTES
        || !secret.len().is_multiple_of(2)
        || !lowercase_hex(secret)
    {
        return Err(invalid());
    }
    let mut decoded = Zeroizing::new(vec![0; secret.len() / 2]);
    hex::decode_to_slice(secret, decoded.as_mut_slice()).map_err(|_| invalid())?;
    let passphrase = std::str::from_utf8(&decoded).map_err(|_| invalid())?;
    Ok(SecretString::new(Box::<str>::from(passphrase)))
}

pub(super) fn lowercase_hex(text: &str) -> bool {
    text.bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

pub(super) fn canonical(value: &mut Value) -> io::Result<Vec<u8>> {
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
#[allow(clippy::expect_used, clippy::panic)]
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
        assert!(
            request(&mut frame.as_slice(), false)
                .expect("decode")
                .is_some()
        );
    }

    #[test]
    fn v2_submit_consumes_a_bounded_canonical_secret_without_a_json_value() {
        use secrecy::ExposeSecret as _;
        let uuid = "10000000-0000-4000-8000-000000000001";
        let digest = "a".repeat(64);
        let encoded = hex::encode("synthetic café");
        let mut body = json!({"id":3, "method":"approval_submit", "params":{
            "case_id":uuid, "presentation":uuid, "view_sha256":digest,
            "method":"keystore_passphrase", "passphrase_hex":encoded,
        }});
        let raw = canonical(&mut body).expect("synthetic frame");
        assert!(approval_submission(&raw, false).is_err());
        let req = approval_submission(&raw, true)
            .expect("frame")
            .expect("submitted");
        assert!(req.params.is_null());
        let Credential::Passphrase(phrase) = req.submission.expect("phrase").credential else {
            panic!("wrong synthetic credential");
        };
        assert_eq!(phrase.expose_secret(), "synthetic café");
        for invalid_secret in [
            "AA".to_owned(),
            "ff".to_owned(),
            "123".to_owned(),
            "aa".repeat(MAX_PASSPHRASE_BYTES + 1),
        ] {
            body["params"]["passphrase_hex"] = json!(invalid_secret);
            let bytes = canonical(&mut body).expect("synthetic invalid frame");
            assert!(approval_submission(&bytes, true).is_err());
        }
        body["params"]["passphrase_hex"] = json!(null);
        body["params"]["method"] = json!("windows_hello");
        let req = approval_submission(&canonical(&mut body).expect("canonical frame"), true)
            .expect("native submission")
            .expect("submission");
        assert!(matches!(
            req.submission.expect("credential").credential,
            Credential::WindowsHello
        ));
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
            assert!(request(&mut framed.as_slice(), false).is_err(), "{payload}");
        }
        for mut bad in [
            &0u32.to_be_bytes()[..],
            &65_537u32.to_be_bytes()[..],
            &[0, 0, 0, 8, b'{'],
        ] {
            assert!(request(&mut bad, false).is_err());
        }
        let deep = (0..MAX_DEPTH).fold(Value::Null, |child, _| Value::Array(vec![child]));
        assert!(frame(deep).is_err());
        assert!(frame(Value::Array(vec![Value::Null; MAX_NODES])).is_err());
        assert!(read_magic(&mut &b"IRMIND-RPC-V2\0"[..], MAGIC).is_err());
    }
}
