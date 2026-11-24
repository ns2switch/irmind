//! The V10 export ends with mandatory Sigma and report object counts.
use super::{AppError, CancellationToken, storage, storage_reason};
use irmind_app::v10_proofs::{V10ProofFamily, write_v10_object_section};
use std::io::{Read, Write};

const FAMILIES: [V10ProofFamily; 2] = [V10ProofFamily::Sigma, V10ProofFamily::Report];

pub(super) fn write_empty(
    output: &mut impl Write,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    for family in FAMILIES {
        write_v10_object_section(
            output,
            family,
            &[],
            |_| Err::<std::io::Empty, _>(AppError::InvalidChain(0)),
            cancel,
        )?;
    }
    Ok(())
}

pub(super) fn verify_empty(input: &mut impl Read) -> Result<(), AppError> {
    for _ in FAMILIES {
        let mut count = [0; 8];
        input.read_exact(&mut count).map_err(storage)?;
        if count != [0; 8] {
            return Err(AppError::InvalidChain(0));
        }
    }
    if input.read(&mut [0]).map_err(storage)? != 0 {
        return Err(storage_reason("export has trailing bytes"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::export_current::{HeaderV10, write_header};
    use super::super::{CaseSeal, hex, sha256};
    use super::*;
    use std::io::{Seek as _, SeekFrom};

    #[test]
    fn export_v10_wire_matches_independent_header_and_count_vectors() {
        let vectors: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../testkit/fixtures/contracts/sigma_report_v10.json"
        ))
        .unwrap();
        let key = (0..32).collect::<Vec<u8>>();
        let header = HeaderV10 {
            version: 10,
            case_id: "00000000-0000-4000-8000-000000000010".into(),
            title: "Synthetic V10 layout".into(),
            severity: "low".into(),
            scope: "synthetic case".into(),
            seal: CaseSeal {
                seq: 7,
                hash: sha256(b"synthetic-audit-entry"),
                sig: (0..64).collect(),
                analyst_key_fingerprint: hex(&sha256(&key)),
                public_key: key,
            },
        };
        let mut file = tempfile::tempfile().unwrap();
        write_header(&mut file, &header).unwrap();
        let mut bytes = Vec::new();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_to_end(&mut bytes).unwrap();
        let vector = &vectors["export_v10_header_frame"];
        assert_eq!(hex(&bytes), vector["bytes_hex"]);
        assert_eq!(hex(&sha256(&bytes)), vector["sha256"]);

        bytes.clear();
        let cancel = CancellationToken::new();
        write_empty(&mut bytes, &cancel).unwrap();
        let vector = &vectors["export_v10_empty_sigma_and_report_counts"];
        assert_eq!(hex(&bytes), vector["bytes_hex"]);
        assert_eq!(hex(&sha256(&bytes)), vector["sha256"]);
        verify_empty(&mut bytes.as_slice()).unwrap();
        for index in [7, 15] {
            bytes[index] = 1;
            assert!(verify_empty(&mut bytes.as_slice()).is_err());
            bytes[index] = 0;
        }
        assert!(verify_empty(&mut &bytes[..15]).is_err());
        bytes.push(0);
        assert!(verify_empty(&mut bytes.as_slice()).is_err());
    }
}
