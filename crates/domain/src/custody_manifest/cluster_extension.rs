use super::{DomainError, Reader, put};
use crate::SourceClusterContext;
use sha2::{Digest as _, Sha256};
const TAG: &[u8] = b"irmind-acquisition-clusters-v1";
// The base source codec stays fixed. This descriptor binds the optional record suffix.
const RECORD_CONTRACT: &[u8] = b"irmind-source-record-cluster-v1;optional-suffix=tag-nul,provider-text,id-text;length-prefix-u64-be;identity=utf8-exact-v1;context=irmind-source-cluster-context-v1;providers=kubernetes:0,eks:1,gke:2,aks:3;basis=analyst:0,command:1,confirmed-source:2;bindings=1..8;id-bytes=512";
/// No extension bytes means absent context, not a historical decoding route.
pub(super) fn write(out: &mut Vec<u8>, context: Option<&SourceClusterContext>) {
    if let Some(context) = context {
        put(out, TAG);
        put(out, &context.encode());
        put(out, &Sha256::digest(RECORD_CONTRACT));
    }
}
pub(super) fn read(reader: &mut Reader<'_>) -> Result<Option<SourceClusterContext>, DomainError> {
    if reader.rest.is_empty() {
        return Ok(None);
    }
    if reader.bytes_limit(TAG.len())? != TAG {
        return Err(DomainError::InvalidManifest);
    }
    let context = SourceClusterContext::decode(reader.bytes_limit(8192)?)?;
    if reader.bytes_limit(32)? != Sha256::digest(RECORD_CONTRACT).as_slice() {
        return Err(DomainError::InvalidManifest);
    }
    Ok(Some(context))
}
