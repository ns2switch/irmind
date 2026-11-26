//! Public catalog downloads, invoked only by an explicit Analyst request.
mod transport;
#[cfg(feature = "sigma")]
pub(super) async fn fetch_sigmahq(
    url: &str,
    limit: usize,
    cancel: &CancellationToken,
) -> Result<Vec<u8>, AppError> {
    transport::fetch_sigmahq(url, limit, cancel).await
}
use irmind_app::catalog::{
    AnalystCatalogRequest, BoundedPackageBytes, CatalogAsset, CatalogIndexBytes,
    CatalogReleaseMetadata, PortFuture, SkillCatalogSource, VerifiedCatalogRelease,
};
use irmind_app::{AppError, CancellationToken};
#[cfg(feature = "sigma")]
pub(super) async fn fetch_sigma_asset(
    url: &str,
    limit: usize,
    cancel: &CancellationToken,
) -> Result<Vec<u8>, AppError> {
    transport::fetch(url, limit, cancel).await
}
pub(super) struct GitHubCatalogSource;
const REPOSITORY: &str = "ns2switch/irmind-skills";
impl SkillCatalogSource for GitHubCatalogSource {
    fn index<'a>(
        &'a self,
        request: &'a AnalystCatalogRequest,
        cancel: &'a CancellationToken,
    ) -> PortFuture<'a, CatalogIndexBytes> {
        Box::pin(async move {
            available()?;
            let suffix = request
                .tag()
                .map_or_else(|| "latest".into(), |tag| format!("tags/{}", tag.tag()));
            let metadata = transport::fetch(
                &format!("https://api.github.com/repos/{REPOSITORY}/releases/{suffix}"),
                1024 * 1024,
                cancel,
            )
            .await?;
            let metadata = CatalogReleaseMetadata::decode(&metadata, request.tag().is_none())?;
            if request.tag().is_some_and(|tag| tag.tag() != metadata.tag()) {
                return Err(irmind_app::catalog::CatalogError::ReleaseMismatch.into());
            }
            let base = format!(
                "https://github.com/{REPOSITORY}/releases/download/{}",
                metadata.tag()
            );
            let index =
                transport::fetch(&format!("{base}/index.json"), 1024 * 1024, cancel).await?;
            let signature = transport::fetch(&format!("{base}/index.ed25519"), 64, cancel).await?;
            Ok(CatalogIndexBytes::new(index, &signature)?.with_resolved_tag(metadata.tag())?)
        })
    }
    fn package<'a>(
        &'a self,
        release: &'a VerifiedCatalogRelease,
        asset: &'a CatalogAsset,
        cancel: &'a CancellationToken,
    ) -> PortFuture<'a, BoundedPackageBytes> {
        Box::pin(async move {
            available()?;
            if release.index_hash() != asset.index_hash() {
                return Err(irmind_app::catalog::CatalogError::ReleaseMismatch.into());
            }
            let url = format!(
                "https://github.com/{REPOSITORY}/releases/download/{}/{}",
                release.tag(),
                asset.entry().asset()
            );
            let bytes = transport::fetch(&url, 1024 * 1024, cancel).await?;
            asset.check_bytes(&bytes)?;
            Ok(BoundedPackageBytes::new(bytes)?)
        })
    }
}
fn available() -> Result<(), AppError> {
    if !irmind_infra::Ed25519CatalogIndexVerifier::production()?.available() {
        return Err(irmind_app::catalog::CatalogError::Unavailable.into());
    }
    Ok(())
}
