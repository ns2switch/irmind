//! Explicit acquisition context; cluster identities never grant read permissions.
use crate::DomainError;
mod codec;

pub const MAX_SOURCE_CLUSTERS: usize = 8;
pub const MAX_CLUSTER_ID_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ClusterProvider {
    Kubernetes,
    Eks,
    Gke,
    Aks,
}
impl ClusterProvider {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Kubernetes => "kubernetes",
            Self::Eks => "eks",
            Self::Gke => "gke",
            Self::Aks => "aks",
        }
    }
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "kubernetes" => Ok(Self::Kubernetes),
            "eks" => Ok(Self::Eks),
            "gke" => Ok(Self::Gke),
            "aks" => Ok(Self::Aks),
            _ => Err(invalid()),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClusterContextBasis {
    Analyst,
    Command,
    ConfirmedSource,
}
impl ClusterContextBasis {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Analyst => "analyst",
            Self::Command => "command",
            Self::ConfirmedSource => "confirmed_source",
        }
    }
}

/// UTF-8-exact-v1: no case folding or Unicode equivalence is invented for identity.
/// Physical partition normalization is separate and never changes this value.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ClusterIdentity {
    provider: ClusterProvider,
    id: String,
}
impl ClusterIdentity {
    pub fn try_new(provider: ClusterProvider, id: &str) -> Result<Self, DomainError> {
        if id.is_empty()
            || id.len() > MAX_CLUSTER_ID_BYTES
            || id.trim() != id
            || id.chars().any(invalid_identity_char)
            || id.contains(['\\', '*', '?', '#', '@'])
            || id.split(['/', ':']).any(|s| matches!(s, "." | ".."))
            || !(id.contains(':')
                || id.starts_with("projects/")
                || id.starts_with("/subscriptions/"))
        {
            return Err(invalid());
        }
        Ok(Self {
            provider,
            id: id.into(),
        })
    }
    pub fn parse_qualified(value: &str) -> Result<Self, DomainError> {
        let (provider, id) = value.split_once(':').ok_or_else(invalid)?;
        Self::try_new(ClusterProvider::parse(provider)?, id)
    }
    pub const fn provider(&self) -> ClusterProvider {
        self.provider
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    /// A collision-free query identity, including the source provider.
    pub fn qualified(&self) -> String {
        format!("{}:{}", self.provider.as_str(), self.id)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceClusterBinding {
    identity: ClusterIdentity,
    basis: ClusterContextBasis,
}
impl SourceClusterBinding {
    pub fn try_new(
        identity: ClusterIdentity,
        basis: ClusterContextBasis,
        confirmed_claim: Option<&str>,
    ) -> Result<Self, DomainError> {
        match (basis, confirmed_claim) {
            (ClusterContextBasis::ConfirmedSource, Some(claim)) if claim == identity.id() => {}
            (ClusterContextBasis::Analyst | ClusterContextBasis::Command, None) => {}
            _ => return Err(invalid()),
        }
        Ok(Self { identity, basis })
    }
    pub const fn identity(&self) -> &ClusterIdentity {
        &self.identity
    }
    pub const fn basis(&self) -> ClusterContextBasis {
        self.basis
    }
}
/// A single explicit default, or up to eight exact, analyst-confirmed wrapper claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceClusterContext {
    bindings: Vec<SourceClusterBinding>,
}
impl SourceClusterContext {
    pub fn try_new(mut bindings: Vec<SourceClusterBinding>) -> Result<Self, DomainError> {
        if bindings.is_empty()
            || bindings.len() > MAX_SOURCE_CLUSTERS
            || (bindings.len() > 1
                && bindings
                    .iter()
                    .any(|b| b.basis != ClusterContextBasis::ConfirmedSource))
        {
            return Err(invalid());
        }
        bindings.sort_by(|a, b| a.identity.cmp(&b.identity));
        if bindings.windows(2).any(|p| p[0].identity == p[1].identity) {
            return Err(invalid());
        }
        Ok(Self { bindings })
    }
    pub fn bindings(&self) -> &[SourceClusterBinding] {
        &self.bindings
    }
    pub fn resolve(
        &self,
        claim: Option<&ClusterIdentity>,
    ) -> Result<&ClusterIdentity, DomainError> {
        if let Some(claim) = claim {
            return self
                .bindings
                .iter()
                .find(|b| &b.identity == claim)
                .map(|b| &b.identity)
                .ok_or_else(invalid);
        }
        if let [binding] = self.bindings.as_slice()
            && binding.basis != ClusterContextBasis::ConfirmedSource
        {
            return Ok(&binding.identity);
        }
        Err(invalid())
    }
    pub fn contains(&self, identity: &ClusterIdentity) -> bool {
        self.bindings
            .iter()
            .any(|binding| &binding.identity == identity)
    }
    pub fn encode(&self) -> Vec<u8> {
        codec::encode(self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, DomainError> {
        codec::decode(bytes)
    }
}
fn invalid_identity_char(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
}
fn invalid() -> DomainError {
    DomainError::InvalidManifest
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
