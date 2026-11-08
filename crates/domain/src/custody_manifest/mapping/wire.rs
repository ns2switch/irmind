use super::{DomainError, invalid};
use crate::custody_manifest::{HEX_DIGITS, hex_digit};
use crate::custody_manifest::{Reader, put};
use crate::{EvidenceHash, MappingIdentityV1};

pub(super) const MAX_SMALL: usize = 16 * 1024;
pub(super) const MAX_ARTIFACT: usize = 16 * 1024;
/// Hex payload plus the signed-entry envelope stays below the 1 MiB frame limit.
pub(super) const MAX_METADATA: usize = 480 * 1024;

pub(super) fn encode(bytes: &[u8], limit: usize) -> Result<String, DomainError> {
    if bytes.len() > limit {
        return Err(invalid());
    }
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(HEX_DIGITS[usize::from(byte & 15)]));
    }
    Ok(out)
}

pub(super) fn decode(payload: &str, tag: &[u8], limit: usize) -> Result<Vec<u8>, DomainError> {
    if payload.len() > limit * 2 || !payload.len().is_multiple_of(2) {
        return Err(invalid());
    }
    let mut bytes = Vec::with_capacity(payload.len() / 2);
    for pair in payload.as_bytes().chunks_exact(2) {
        bytes.push(hex_digit(pair[0])? << 4 | hex_digit(pair[1])?);
    }
    if !bytes.starts_with(tag) {
        return Err(invalid());
    }
    Ok(bytes)
}

pub(super) fn id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b))
}
pub(super) fn version(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|b| b.is_ascii_graphic())
}

pub(super) fn write_mapping(out: &mut Vec<u8>, identity: &MappingIdentityV1) {
    for value in [
        identity.id(),
        identity.version(),
        identity.target(),
        identity.implementation().as_str(),
    ] {
        put(out, value.as_bytes());
    }
}
pub(super) fn read_mapping(r: &mut Reader<'_>) -> Result<MappingIdentityV1, DomainError> {
    MappingIdentityV1::try_new(
        &r.string_limit(64)?,
        &r.string_limit(128)?,
        &r.string_limit(128)?,
        EvidenceHash::parse(&r.string_limit(64)?)?,
    )
    .map_err(|_| invalid())
}
