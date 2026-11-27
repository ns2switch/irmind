//! Version admission for a local case and its portable export.
use crate::{Actor, AppError, AuditEventKind, CaseId, FixedAppError, SignedEntry};
use serde::Deserialize;
use std::fmt;
use std::io::Read;

pub(crate) const CASE_VERSION: u8 = 7;
pub const EXPORT_VERSION: u32 = 11;
pub const EXPORT_MAGIC: &[u8] = b"IRMIND-EXPORT-V11\0";
pub const FORMAT_GUIDE: &str =
    "https://github.com/ns2switch/irmind/blob/main/docs/previous-versions.md";
pub const MAX_CASE_ROOT_BYTES: usize = 1024 * 1024;
const BINARY_DOWNLOAD: &str = "Download the exact tag from GitHub Releases and verify its SHA-256 checksum, Sigstore bundle and GitHub attestation. If you have open older cases, keep a verified copy before upgrading. Homebrew does not keep old versions.";
const OLD_CASE_DELETE: &str = "To delete an old case, use the producing binary, which refuses to delete sealed cases, or remove its case directory manually. Manual removal is irreversible and loses the case files.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaseFormatError {
    Case(Option<u32>),
    Export(u32),
    InvalidExport,
}

impl std::error::Error for CaseFormatError {}

impl fmt::Display for CaseFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let producer = match *self {
            Self::Case(version) => {
                if let Some(version) = version {
                    write!(f, "This build cannot read case format {version}. ")?;
                } else {
                    f.write_str("This build cannot read this case layout. ")?;
                }
                match version {
                    Some(6) => "IRMind v0.7.x",
                    Some(5) => "IRMind v0.6.x",
                    Some(4) => "IRMind v0.5.x",
                    Some(version) if version > u32::from(CASE_VERSION) => {
                        "the newer IRMind version"
                    }
                    _ => "the IRMind version",
                }
            }
            Self::Export(version) => {
                write!(f, "This build cannot read export V{version}. ")?;
                match version {
                    10 => "IRMind v0.7.x",
                    9 => "IRMind v0.6.x",
                    8 => "IRMind v0.5.x",
                    7 => "IRMind v0.4.x",
                    6 => "IRMind v0.3.x",
                    version if version > EXPORT_VERSION => "the newer IRMind version",
                    _ => "the IRMind version",
                }
            }
            Self::InvalidExport => return f.write_str("Invalid case export format"),
        };
        write!(
            f,
            "Use the exact {producer} binary that created it, or re-ingest the verified originals into a new case. {BINARY_DOWNLOAD}"
        )?;
        if matches!(self, Self::Case(_)) {
            write!(f, " {OLD_CASE_DELETE}")?;
        }
        write!(f, " See {FORMAT_GUIDE}")
    }
}

fn unsupported(error: CaseFormatError) -> AppError {
    AppError::Fixed(FixedAppError::CaseFormat(error))
}

/// Interpret the bounded first checkpoint after checking its signature.
pub fn admit_case_root(first: &SignedEntry) -> Result<(), AppError> {
    #[derive(Deserialize)]
    struct VersionMarker {
        version: u32,
    }
    let invalid = || AppError::InvalidChain(first.seq);
    if first.seq != 1
        || first.kind != AuditEventKind::CaseCreated
        || first.actor != Actor::Analyst
        || first.prev != [0; 32]
        || first.evidence.is_some()
        || first.payload.len() > MAX_CASE_ROOT_BYTES
        || !matches!(first.origin.as_str(), "system" | "analyst")
        || CaseId::parse(&first.case_id).is_err()
    {
        return Err(invalid());
    }
    let payload = first.payload.trim_start();
    if !payload.starts_with('{') {
        return if payload.is_empty() || payload.starts_with(['[', '"']) {
            Err(invalid())
        } else {
            Err(unsupported(CaseFormatError::Case(None)))
        };
    }
    let marker: VersionMarker = serde_json::from_str(payload).map_err(|_| invalid())?;
    if marker.version == 0 {
        return Err(invalid());
    }
    if marker.version != u32::from(CASE_VERSION) {
        return Err(unsupported(CaseFormatError::Case(Some(marker.version))));
    }
    Ok(())
}

/// Read only the canonical magic, including its terminator. Old archives never
/// reach header allocation or signed record decoding.
pub fn read_export_magic(reader: &mut impl Read) -> Result<(), AppError> {
    const PREFIX: &[u8] = b"IRMIND-EXPORT-V";
    let invalid = || unsupported(CaseFormatError::InvalidExport);
    let mut magic = [0; PREFIX.len() + 10];
    let mut length = 0;
    loop {
        let mut byte = [0];
        reader.read_exact(&mut byte).map_err(|_| invalid())?;
        if byte[0] == 0 {
            break;
        }
        *magic.get_mut(length).ok_or_else(invalid)? = byte[0];
        length += 1;
    }
    let digits = magic[..length].strip_prefix(PREFIX).ok_or_else(invalid)?;
    if digits.is_empty() || digits[0] == b'0' || !digits.iter().all(u8::is_ascii_digit) {
        return Err(invalid());
    }
    let version = std::str::from_utf8(digits)
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(invalid)?;
    if version != EXPORT_VERSION {
        return Err(unsupported(CaseFormatError::Export(version)));
    }
    Ok(())
}

pub fn check_export_header_version(version: u32) -> Result<(), AppError> {
    if version == EXPORT_VERSION {
        Ok(())
    } else {
        Err(unsupported(CaseFormatError::InvalidExport))
    }
}
