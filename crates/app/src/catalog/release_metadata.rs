//! Bounded transport metadata only; never publisher authentication or case data.
use super::{CatalogError, FrozenCatalogRelease};
use serde::Deserialize;
#[derive(Deserialize)]
pub struct CatalogReleaseMetadata {
    tag_name: String,
    draft: bool,
    prerelease: bool,
}
impl CatalogReleaseMetadata {
    pub fn decode(bytes: &[u8], latest: bool) -> Result<Self, CatalogError> {
        super::limits::check(bytes)?;
        let metadata: Self =
            serde_json::from_slice(bytes).map_err(|_| CatalogError::InvalidData)?;
        FrozenCatalogRelease::new(&metadata.tag_name)?;
        if metadata.draft || latest && metadata.prerelease {
            return Err(CatalogError::ReleaseMismatch);
        }
        Ok(metadata)
    }
    pub fn tag(&self) -> &str {
        &self.tag_name
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn catalog_release_metadata_is_bounded_non_draft_and_explicit_about_prereleases() {
        assert_eq!(
            CatalogReleaseMetadata::decode(
                br#"{"tag_name":"v1.2.3","draft":false,"prerelease":false,"assets":[]}"#,
                true
            )
            .unwrap()
            .tag(),
            "v1.2.3"
        );
        for bad in [
            br#"{"tag_name":"v1.2.3","tag_name":"v1.2.4","draft":false,"prerelease":false}"#
                .as_slice(),
            br#"{"tag_name":"v1.2.3","draft":true,"prerelease":false}"#,
            br#"{"tag_name":"../x","draft":false,"prerelease":false}"#,
        ] {
            assert!(CatalogReleaseMetadata::decode(bad, true).is_err());
        }
        let pre = br#"{"tag_name":"v1.2.3-rc.1","draft":false,"prerelease":true}"#;
        assert!(CatalogReleaseMetadata::decode(pre, true).is_err());
        assert!(CatalogReleaseMetadata::decode(pre, false).is_ok());
    }
}
