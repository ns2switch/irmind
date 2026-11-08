use super::{DomainError, EvidenceHash, invalid};
use crate::custody_manifest::{Reader, put};
use sha2::{Digest, Sha256};

// Versioned normative descriptor; changes require a new source contract.
const SOURCE_CONTRACT: &[u8] = concat!(
    "irmind-source-record-v1;utf8-byte-sorted-unique-object-keys;array-order;",
    "null=0,bool=1,number-lexeme=2,text=3,bytes=4,array=5,object=6;",
    "record-bytes=4194304,nodes=4096,depth=32,number-bytes=128;",
    "source-sha256,ordinal,optional-real-offset,decoder,source-reference,",
    "source-kind,acquisition,optional-indexed-time,format,discriminators,",
    "typed-fields,partial,members,optional-raw;length-prefix-u64-be"
)
.as_bytes();

pub fn source_record_contract_digest() -> EvidenceHash {
    digest(b"irmind-source-contract-v1\0", SOURCE_CONTRACT)
}
pub fn common_event_contract_digest() -> EvidenceHash {
    digest(
        b"irmind-common-contract-v1\0",
        include_bytes!("../../common_event/goldens/codes-v1.tsv"),
    )
}
fn digest(tag: &[u8], content: &[u8]) -> EvidenceHash {
    let mut hash = Sha256::new();
    hash.update(tag);
    hash.update((content.len() as u64).to_be_bytes());
    hash.update(content);
    EvidenceHash::from_bytes(hash.finalize().into())
}
pub(super) fn write(out: &mut Vec<u8>) {
    for hash in [
        source_record_contract_digest(),
        common_event_contract_digest(),
    ] {
        put(out, hash.as_str().as_bytes());
    }
}
pub(super) fn read(reader: &mut Reader<'_>) -> Result<(), DomainError> {
    for expected in [
        source_record_contract_digest(),
        common_event_contract_digest(),
    ] {
        if reader.string_limit(64)? != expected.as_str() {
            return Err(invalid());
        }
    }
    Ok(())
}
