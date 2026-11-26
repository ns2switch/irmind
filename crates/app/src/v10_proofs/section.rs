//! Stream-authenticate V10 object sections. Keep offsets instead of retaining report bytes.
use super::{V10ProofDescriptor, V10ProofFamily, v10_proof_commitment};
use crate::{AppError, CancellationToken};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Seek, SeekFrom, Write},
};

const MAX_SECTION: u64 = 128 * 1024 * 1024;
const MAX_OBJECTS: u64 = 1_000_000;
const BUFFER: usize = 32 * 1024;
type ObjectKey = (u8, [u8; 32]);

pub struct V10ObjectSection {
    family: V10ProofFamily,
    objects: BTreeMap<ObjectKey, (u64, V10ProofDescriptor)>,
}

impl V10ObjectSection {
    pub fn scan(
        input: &mut (impl Read + Seek),
        family: V10ProofFamily,
        cancel: &CancellationToken,
    ) -> Result<Self, AppError> {
        let mut count = [0; 8];
        input.read_exact(&mut count).map_err(|_| invalid())?;
        let count = u64::from_be_bytes(count);
        if count > MAX_OBJECTS {
            return Err(invalid());
        }
        let mut previous = None;
        let mut objects = BTreeMap::new();
        let mut remaining = MAX_SECTION;
        let mut scratch = vec![0; BUFFER];
        for _ in 0..count {
            check_cancel(cancel)?;
            let mut raw = [0; V10ProofDescriptor::BYTE_LEN];
            input.read_exact(&mut raw).map_err(|_| invalid())?;
            let descriptor = V10ProofDescriptor::decode(family, &raw).map_err(|_| invalid())?;
            let key = (descriptor.kind(), descriptor.hash());
            if previous.is_some_and(|previous| previous >= key) {
                return Err(invalid());
            }
            previous = Some(key);
            remaining = remaining
                .checked_sub(descriptor.size())
                .ok_or_else(invalid)?;
            let offset = input.stream_position().map_err(|_| invalid())?;
            check_body(input, descriptor, &mut scratch, cancel)?;
            objects.insert(key, (offset, descriptor));
        }
        Ok(Self { family, objects })
    }

    pub fn descriptor(&self, key: ObjectKey) -> Result<V10ProofDescriptor, AppError> {
        self.objects
            .get(&key)
            .map(|(_, descriptor)| *descriptor)
            .ok_or_else(invalid)
    }

    pub fn descriptors_of_kind(&self, kind: u8) -> impl Iterator<Item = V10ProofDescriptor> + '_ {
        self.objects
            .range((kind, [0; 32])..=(kind, [u8::MAX; 32]))
            .map(|(_, (_, descriptor))| *descriptor)
    }

    pub fn body(
        &self,
        input: &mut (impl Read + Seek),
        key: ObjectKey,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        let (offset, descriptor) = self.objects.get(&key).ok_or_else(invalid)?;
        check_cancel(cancel)?;
        input
            .seek(SeekFrom::Start(*offset))
            .map_err(|_| invalid())?;
        let mut body = vec![0; usize::try_from(descriptor.size()).map_err(|_| invalid())?];
        input.read_exact(&mut body).map_err(|_| invalid())?;
        check_cancel(cancel)?;
        let observed = V10ProofDescriptor::from_body(self.family, descriptor.kind(), &body)
            .map_err(|_| invalid())?;
        if observed != *descriptor {
            return Err(invalid());
        }
        Ok(body)
    }

    pub fn check_commitment(
        &self,
        keys: &BTreeSet<ObjectKey>,
        expected: &[u8; 32],
    ) -> Result<(), AppError> {
        let descriptors = keys
            .iter()
            .map(|key| {
                self.objects
                    .get(key)
                    .map(|(_, descriptor)| *descriptor)
                    .ok_or_else(invalid)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let actual = v10_proof_commitment(self.family, &descriptors).map_err(|_| invalid())?;
        if &actual != expected {
            return Err(invalid());
        }
        Ok(())
    }

    pub fn check_union(&self, referenced: &BTreeSet<ObjectKey>) -> Result<(), AppError> {
        if !self.objects.keys().eq(referenced.iter()) {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Write one bounded V10 section to a transactional export sink.
pub fn write_v10_object_section<R: Read>(
    output: &mut impl Write,
    family: V10ProofFamily,
    objects: &[V10ProofDescriptor],
    mut open: impl FnMut(V10ProofDescriptor) -> Result<R, AppError>,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    let count = u64::try_from(objects.len()).map_err(|_| invalid())?;
    if count > MAX_OBJECTS {
        return Err(invalid());
    }
    v10_proof_commitment(family, objects).map_err(|_| invalid())?;
    check_cancel(cancel)?;
    output
        .write_all(&count.to_be_bytes())
        .map_err(|_| invalid())?;
    if objects.is_empty() {
        return Ok(());
    }
    let mut scratch = vec![0; BUFFER];
    for descriptor in objects {
        check_cancel(cancel)?;
        let mut input = open(*descriptor)?;
        output
            .write_all(&descriptor.encode())
            .map_err(|_| invalid())?;
        let mut remaining = descriptor.size();
        let mut digest = Sha256::new();
        while remaining > 0 {
            check_cancel(cancel)?;
            let length = usize::try_from(remaining.min(BUFFER as u64)).map_err(|_| invalid())?;
            input
                .read_exact(&mut scratch[..length])
                .map_err(|_| invalid())?;
            digest.update(&scratch[..length]);
            output
                .write_all(&scratch[..length])
                .map_err(|_| invalid())?;
            remaining -= length as u64;
        }
        let actual: [u8; 32] = digest.finalize().into();
        if actual != descriptor.hash() || input.read(&mut [0]).map_err(|_| invalid())? != 0 {
            return Err(invalid());
        }
    }
    Ok(())
}

fn check_body(
    input: &mut impl Read,
    descriptor: V10ProofDescriptor,
    scratch: &mut [u8],
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    let mut remaining = descriptor.size();
    let mut digest = Sha256::new();
    while remaining != 0 {
        check_cancel(cancel)?;
        let length = usize::try_from(remaining.min(BUFFER as u64)).map_err(|_| invalid())?;
        input
            .read_exact(&mut scratch[..length])
            .map_err(|_| invalid())?;
        digest.update(&scratch[..length]);
        remaining -= length as u64;
    }
    let actual: [u8; 32] = digest.finalize().into();
    if actual != descriptor.hash() {
        return Err(invalid());
    }
    Ok(())
}

fn check_cancel(cancel: &CancellationToken) -> Result<(), AppError> {
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    Ok(())
}

fn invalid() -> AppError {
    AppError::InvalidChain(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn proof_sections_authenticate_exact_order_bodies_and_references() {
        let body = super::super::report_objects::tests::object("sigma_raw_rule");
        let family = V10ProofFamily::Sigma;
        let descriptor = V10ProofDescriptor::from_body(family, 1, &body).unwrap();
        let key = (descriptor.kind(), descriptor.hash());
        let mut bytes = 1u64.to_be_bytes().to_vec();
        bytes.extend_from_slice(&descriptor.encode());
        bytes.extend_from_slice(&body);
        let cancel = CancellationToken::new();
        let mut encoded = Vec::new();
        write_v10_object_section(
            &mut encoded,
            family,
            &[descriptor],
            |_| Ok(Box::new(Cursor::new(body.as_slice()))),
            &cancel,
        )
        .unwrap();
        assert_eq!(encoded, bytes);
        let mut wrong_body = body.clone();
        wrong_body.push(0);
        assert!(
            write_v10_object_section(
                &mut Vec::new(),
                family,
                &[descriptor],
                |_| Ok(Box::new(Cursor::new(wrong_body.as_slice()))),
                &cancel,
            )
            .is_err()
        );
        let mut cursor = Cursor::new(&bytes);
        let index = V10ObjectSection::scan(&mut cursor, family, &cancel).unwrap();
        assert_eq!(cursor.position(), bytes.len() as u64);
        assert_eq!(index.body(&mut cursor, key, &cancel).unwrap(), body);
        assert!(index.check_union(&BTreeSet::new()).is_err());
        let keys = BTreeSet::from([key]);
        let commitment = v10_proof_commitment(family, &[descriptor]).unwrap();
        index.check_union(&keys).unwrap();
        index.check_commitment(&keys, &commitment).unwrap();
        assert!(index.check_commitment(&keys, &[0; 32]).is_err());
        let missing = BTreeSet::from([(0, descriptor.hash())]);
        assert!(index.check_commitment(&missing, &commitment).is_err());

        let mut corrupt = bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(V10ObjectSection::scan(&mut Cursor::new(&corrupt), family, &cancel).is_err());
        assert!(
            index
                .body(&mut Cursor::new(&corrupt), key, &cancel)
                .is_err()
        );
        let mut duplicate = bytes.clone();
        duplicate[..8].copy_from_slice(&2u64.to_be_bytes());
        duplicate.extend_from_slice(&bytes[8..]);
        assert!(V10ObjectSection::scan(&mut Cursor::new(&duplicate), family, &cancel).is_err());
        cancel.cancel();
        assert!(matches!(
            V10ObjectSection::scan(&mut Cursor::new(&bytes), family, &cancel),
            Err(AppError::Cancelled)
        ));
    }
}
