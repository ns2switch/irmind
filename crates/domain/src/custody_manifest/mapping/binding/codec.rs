use super::{
    DomainError, EvidenceHash, MappingBindingV1, MappingInputRefV1, SourceDecoderIdentityV1,
};
use crate::custody_manifest::mapping::wire;
use crate::custody_manifest::{Reader, put};
impl MappingBindingV1 {
    pub(in crate::custody_manifest::mapping) fn write(&self, out: &mut Vec<u8>) {
        for hash in [
            self.input().source(),
            self.input().set(),
            self.profile(),
            self.catalog(),
        ] {
            put(out, hash.as_str().as_bytes());
        }
        out.extend_from_slice(&self.input().records().to_be_bytes());
        put(out, self.decoder().id().as_bytes());
        put(out, self.decoder().version().as_bytes());
        out.push(u8::from(self.mapping().is_some()));
        if let Some(mapping) = self.mapping() {
            wire::write_mapping(out, mapping);
        }
    }
    pub(in crate::custody_manifest::mapping) fn read(
        r: &mut Reader<'_>,
    ) -> Result<MappingBindingV1, DomainError> {
        let source = EvidenceHash::parse(&r.string_limit(64)?)?;
        let set = EvidenceHash::parse(&r.string_limit(64)?)?;
        let profile = EvidenceHash::parse(&r.string_limit(64)?)?;
        let catalog = EvidenceHash::parse(&r.string_limit(64)?)?;
        let records = r.u64()?;
        let decoder =
            SourceDecoderIdentityV1::try_new(&r.string_limit(64)?, &r.string_limit(128)?)?;
        let mapping = if r.bool()? {
            Some(wire::read_mapping(r)?)
        } else {
            None
        };
        Ok(MappingBindingV1::new(
            MappingInputRefV1::try_new(source, set, records)?,
            profile,
            catalog,
            decoder,
            mapping,
        ))
    }
}
