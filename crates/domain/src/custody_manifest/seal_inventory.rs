use super::{DigestStream, DomainError, EvidenceHash, Reader, decode_payload, encode_payload, put};

const TAG: &[u8] = b"irmind-seal-inventory-v2\0";
const ITEMS: &[u8] = b"irmind-seal-inventory-items-v2\0";
const ITEM: &[u8] = b"irmind-seal-inventory-item-v2\0";
const MAX_ITEMS: u64 = 10_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum SealItemKind {
    Evidence,
    Source,
    Artifact,
}
impl SealItemKind {
    pub const fn code(self) -> u8 {
        match self {
            Self::Evidence => 0,
            Self::Source => 1,
            Self::Artifact => 2,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealInventoryV2 {
    pub count: u64,
    pub sha256: EvidenceHash,
}

impl SealInventoryV2 {
    pub fn item_hash(
        kind: SealItemKind,
        key: &str,
        payload: &[u8],
        digest: DigestStream,
    ) -> [u8; 32] {
        digest(&mut |feed| {
            feed(ITEM);
            feed(&[kind.code()]);
            feed(&(key.len() as u64).to_be_bytes());
            feed(key.as_bytes());
            feed(&(payload.len() as u64).to_be_bytes());
            feed(payload);
        })
    }
    pub fn from_ordered<'a>(
        mut items: impl ExactSizeIterator<Item = (SealItemKind, &'a str, &'a [u8; 32])>,
        digest: DigestStream,
    ) -> Result<Self, DomainError> {
        let count = u64::try_from(items.len()).map_err(|_| DomainError::InvalidManifest)?;
        if count == 0 || count > MAX_ITEMS {
            return Err(DomainError::InvalidManifest);
        }
        let mut previous = None;
        let mut valid = true;
        let hash = digest(&mut |feed| {
            feed(ITEMS);
            feed(&count.to_be_bytes());
            for (kind, key, item) in items.by_ref() {
                if key.is_empty() || key.len() > 8192 || previous.is_some_and(|p| p >= (kind, key))
                {
                    valid = false;
                }
                previous = Some((kind, key));
                feed(&[kind.code()]);
                feed(&(key.len() as u64).to_be_bytes());
                feed(key.as_bytes());
                feed(item);
            }
        });
        if !valid {
            return Err(DomainError::InvalidManifest);
        }
        Ok(Self {
            count,
            sha256: EvidenceHash::from_bytes(hash),
        })
    }
    pub fn encode(&self) -> Result<String, DomainError> {
        if self.count == 0 || self.count > MAX_ITEMS {
            return Err(DomainError::InvalidManifest);
        }
        let mut bytes = TAG.to_vec();
        bytes.extend_from_slice(&self.count.to_be_bytes());
        put(&mut bytes, self.sha256.as_str().as_bytes());
        encode_payload(&bytes)
    }
    pub fn decode(payload: &str) -> Result<Self, DomainError> {
        let bytes = decode_payload(payload, TAG)?;
        let mut input = Reader::new(&bytes[TAG.len()..]);
        let out = Self {
            count: input.u64()?,
            sha256: EvidenceHash::parse(&input.string_limit(64)?)?,
        };
        input.end()?;
        if out.encode()? != payload {
            return Err(DomainError::InvalidManifest);
        }
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
