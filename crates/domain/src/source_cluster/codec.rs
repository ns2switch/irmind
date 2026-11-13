use super::{
    ClusterContextBasis, ClusterIdentity, ClusterProvider, DomainError, MAX_CLUSTER_ID_BYTES,
    MAX_SOURCE_CLUSTERS, SourceClusterBinding, SourceClusterContext, invalid,
};
const TAG: &[u8] = b"irmind-source-cluster-context-v1\0";
pub(super) fn encode(context: &SourceClusterContext) -> Vec<u8> {
    let mut out = TAG.to_vec();
    out.push(u8::try_from(context.bindings.len()).unwrap_or(u8::MAX));
    for binding in &context.bindings {
        out.push(match binding.identity.provider {
            ClusterProvider::Kubernetes => 0,
            ClusterProvider::Eks => 1,
            ClusterProvider::Gke => 2,
            ClusterProvider::Aks => 3,
        });
        out.push(match binding.basis {
            ClusterContextBasis::Analyst => 0,
            ClusterContextBasis::Command => 1,
            ClusterContextBasis::ConfirmedSource => 2,
        });
        crate::canonical::put(&mut out, binding.identity.id.as_bytes());
    }
    out
}
pub(super) fn decode(bytes: &[u8]) -> Result<SourceClusterContext, DomainError> {
    let mut rest = bytes.strip_prefix(TAG).ok_or_else(invalid)?;
    let count = take(&mut rest)? as usize;
    if !(1..=MAX_SOURCE_CLUSTERS).contains(&count) {
        return Err(invalid());
    }
    let mut bindings = Vec::with_capacity(count);
    for _ in 0..count {
        let provider = match take(&mut rest)? {
            0 => ClusterProvider::Kubernetes,
            1 => ClusterProvider::Eks,
            2 => ClusterProvider::Gke,
            3 => ClusterProvider::Aks,
            _ => return Err(invalid()),
        };
        let basis = match take(&mut rest)? {
            0 => ClusterContextBasis::Analyst,
            1 => ClusterContextBasis::Command,
            2 => ClusterContextBasis::ConfirmedSource,
            _ => return Err(invalid()),
        };
        let length = rest.get(..8).ok_or_else(invalid)?;
        let length = usize::try_from(u64::from_be_bytes(
            length.try_into().map_err(|_| invalid())?,
        ))
        .map_err(|_| invalid())?;
        rest = rest.get(8..).ok_or_else(invalid)?;
        if length > MAX_CLUSTER_ID_BYTES {
            return Err(invalid());
        }
        let id =
            std::str::from_utf8(rest.get(..length).ok_or_else(invalid)?).map_err(|_| invalid())?;
        rest = rest.get(length..).ok_or_else(invalid)?;
        let identity = ClusterIdentity::try_new(provider, id)?;
        let claim = (basis == ClusterContextBasis::ConfirmedSource).then_some(id);
        bindings.push(SourceClusterBinding::try_new(identity, basis, claim)?);
    }
    let context = SourceClusterContext::try_new(bindings)?;
    if !rest.is_empty() || encode(&context) != bytes {
        return Err(invalid());
    }
    Ok(context)
}
fn take(rest: &mut &[u8]) -> Result<u8, DomainError> {
    let value = *rest.first().ok_or_else(invalid)?;
    *rest = &rest[1..];
    Ok(value)
}
