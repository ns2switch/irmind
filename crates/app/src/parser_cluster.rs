//! Acquisition choices remain bounded and separate from policy permissions.
use crate::ClusterIdentity;
#[derive(Clone, Debug)]
pub struct ParserClusterRequirement {
    required: bool,
    /// Exact original wrapper identities, still untrusted until analyst confirmation.
    source_claims: Vec<ClusterIdentity>,
}
impl ParserClusterRequirement {
    pub const fn required(&self) -> bool {
        self.required
    }
    pub fn source_claims(&self) -> &[ClusterIdentity] {
        &self.source_claims
    }
    pub fn try_new(
        required: bool,
        source_claims: Vec<ClusterIdentity>,
    ) -> Result<Self, crate::AppError> {
        if source_claims.len() > irmind_domain::MAX_SOURCE_CLUSTERS
            || !source_claims.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(crate::AppError::Policy(
                "cluster suggestions exceed the bounded source contract".into(),
            ));
        }
        Ok(Self {
            required,
            source_claims,
        })
    }
}
