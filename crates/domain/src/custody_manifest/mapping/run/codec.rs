use super::{
    DomainError, EvidenceHash, MappingCountsV1, MappingRouteV1, MappingRunV1, SetCommitment, TAG,
    invalid,
};
use crate::custody_manifest::mapping::wire;
use crate::custody_manifest::{Reader, put};

impl MappingRunV1 {
    pub fn encode(&self) -> Result<String, DomainError> {
        self.validate_order()?;
        let mut out = TAG.to_vec();
        for hash in [&self.profile, &self.catalog] {
            put(&mut out, hash.as_str().as_bytes());
        }
        out.extend_from_slice(&(self.routes.len() as u64).to_be_bytes());
        for route in &self.routes {
            put(&mut out, route.source.as_str().as_bytes());
            out.push(u8::from(route.mapping.is_some()));
            if let Some(mapping) = &route.mapping {
                wire::write_mapping(&mut out, mapping);
            }
            for count in [
                route.counts.accepted,
                route.counts.unclassified,
                route.counts.unsupported,
                route.counts.missing,
            ] {
                out.extend_from_slice(&count.to_be_bytes());
            }
        }
        out.extend_from_slice(&self.outputs.count.to_be_bytes());
        put(&mut out, self.outputs.sha256.as_str().as_bytes());
        wire::encode(&out, wire::MAX_METADATA)
    }
    pub fn decode(payload: &str) -> Result<Self, DomainError> {
        let bytes = wire::decode(payload, TAG, wire::MAX_METADATA)?;
        let mut r = Reader::new(&bytes[TAG.len()..]);
        let profile = EvidenceHash::parse(&r.string_limit(64)?)?;
        let catalog = EvidenceHash::parse(&r.string_limit(64)?)?;
        let count = r.u64()?;
        if !(1..=8192).contains(&count) {
            return Err(invalid());
        }
        let mut routes = Vec::new();
        for _ in 0..count {
            let source = EvidenceHash::parse(&r.string_limit(64)?)?;
            let mapping = if r.bool()? {
                Some(wire::read_mapping(&mut r)?)
            } else {
                None
            };
            let counts = MappingCountsV1::try_new(r.u64()?, r.u64()?, r.u64()?, r.u64()?)?;
            routes.push(MappingRouteV1::try_new(source, mapping, counts)?);
        }
        let outputs = SetCommitment {
            count: r.u64()?,
            sha256: EvidenceHash::parse(&r.string_limit(64)?)?,
        };
        r.end()?;
        let result = Self {
            profile,
            catalog,
            routes,
            outputs,
        };
        if result.encode()? != payload {
            return Err(invalid());
        }
        Ok(result)
    }
}
