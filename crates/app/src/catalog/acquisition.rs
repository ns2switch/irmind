//! Explicit Analyst requests and immutable previews. No model-facing constructor.
use super::{
    BoundedPackageBytes, CatalogAsset, CatalogIndexBytes, CatalogReceipt, FrozenCatalogRelease,
    VerifiedCatalogIndex, VerifiedCatalogRelease,
};
use crate::{AppError, CancellationToken, CompiledSkill};
use irmind_domain::SkillName;
use std::{collections::BTreeSet, future::Future, pin::Pin};

pub type PortFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AppError>> + Send + 'a>>;
pub trait SkillCatalogSource: Send + Sync {
    fn index<'a>(
        &'a self,
        request: &'a AnalystCatalogRequest,
        cancel: &'a CancellationToken,
    ) -> PortFuture<'a, CatalogIndexBytes>;
    fn package<'a>(
        &'a self,
        release: &'a VerifiedCatalogRelease,
        asset: &'a CatalogAsset,
        cancel: &'a CancellationToken,
    ) -> PortFuture<'a, BoundedPackageBytes>;
}
/// Created only after checking explicit attended Analyst authority.
pub struct AnalystCatalogRequest {
    name: SkillName,
    tag: Option<FrozenCatalogRelease>,
}
impl AnalystCatalogRequest {
    pub const fn name(&self) -> &SkillName {
        &self.name
    }
    pub const fn tag(&self) -> Option<&FrozenCatalogRelease> {
        self.tag.as_ref()
    }
}
/// Guarded, still-unadmitted exact package and publisher claims.
pub struct CatalogInstallPreview {
    pub(crate) skill: CompiledSkill,
    pub(crate) index: VerifiedCatalogIndex,
    pub(crate) receipt: CatalogReceipt,
    pub(crate) previous: Option<String>,
    pub(crate) downgrade: bool,
    pub(crate) differences: String,
}
impl CatalogInstallPreview {
    pub fn differences(&self) -> &str {
        &self.differences
    }
    pub const fn skill(&self) -> &CompiledSkill {
        &self.skill
    }
    pub const fn receipt(&self) -> &CatalogReceipt {
        &self.receipt
    }
    pub const fn downgrade_confirmation_required(&self) -> bool {
        self.downgrade
    }
}
impl crate::Engine<'_> {
    pub fn catalog_request(
        &self,
        name: &str,
        tag: Option<&str>,
    ) -> Result<AnalystCatalogRequest, AppError> {
        self.require_attended_analyst("download a catalog skill")?;
        Ok(AnalystCatalogRequest {
            name: SkillName::parse(name)?,
            tag: tag.map(FrozenCatalogRelease::new).transpose()?,
        })
    }
    pub async fn download_catalog_preview(
        &self,
        source: &dyn SkillCatalogSource,
        request: &AnalystCatalogRequest,
        runtime: &str,
        reserved: &BTreeSet<String>,
        cancel: &CancellationToken,
    ) -> Result<CatalogInstallPreview, AppError> {
        self.require_attended_analyst("download a catalog skill")?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let raw = source.index(request, cancel).await?;
        let frozen = if let Some(tag) = request.tag() {
            if raw
                .resolved_tag
                .as_deref()
                .is_some_and(|resolved| resolved != tag.tag())
            {
                return Err(super::CatalogError::ReleaseMismatch.into());
            }
            FrozenCatalogRelease::new(tag.tag())?
        } else {
            FrozenCatalogRelease::new(
                raw.resolved_tag
                    .as_deref()
                    .ok_or(super::CatalogError::ReleaseMismatch)?,
            )?
        };
        let services = self
            .skill_services()
            .ok_or(crate::SkillServiceError::NotInstalled)?;
        let catalog = services
            .catalog
            .as_ref()
            .ok_or(super::CatalogError::Unavailable)?;
        let index = catalog.verifier.verify(&raw, &frozen)?;
        let asset = index.asset(request.name().as_str())?;
        let package = source.package(&index.release(), &asset, cancel).await?;
        self.build_catalog_preview(index, &asset, &package, (runtime, false), reserved, cancel)
    }
    pub fn preview_catalog_offline(
        &self,
        raw: &CatalogIndexBytes,
        release: &FrozenCatalogRelease,
        package: &BoundedPackageBytes,
        selection: (&str, &str),
        reserved: &BTreeSet<String>,
        cancel: &CancellationToken,
    ) -> Result<CatalogInstallPreview, AppError> {
        self.require_attended_analyst("review an offline catalog skill")?;
        let catalog = self
            .skill_services()
            .and_then(|s| s.catalog.as_ref())
            .ok_or(super::CatalogError::Unavailable)?;
        let index = catalog.verifier.verify(raw, release)?;
        let asset = index.asset(selection.0)?;
        self.build_catalog_preview(
            index,
            &asset,
            package,
            (selection.1, true),
            reserved,
            cancel,
        )
    }
}

pub(crate) fn check_release_history(
    index: &VerifiedCatalogIndex,
    history: &[CatalogReceipt],
) -> Result<bool, AppError> {
    let mut high = 0;
    for old in history {
        high = high.max(old.sequence());
        if (old.release_tag() == index.index().tag() || old.sequence() == index.index().sequence())
            && (old.release_tag() != index.index().tag()
                || old.sequence() != index.index().sequence()
                || old.release_commit() != index.index().commit()
                || old.index_hash() != index.index_hash())
        {
            return Err(AppError::Policy(
                "Catalog release conflicts with a previously accepted tag or sequence.".into(),
            ));
        }
    }
    Ok(index.index().sequence() < high)
}
pub(crate) fn older_or_unknown(candidate: &str, previous: &str) -> bool {
    if candidate == previous {
        return false;
    }
    match (
        super::version::Version::parse(candidate),
        super::version::Version::parse(previous),
    ) {
        (Ok(new), Ok(old)) => new.compare(&old).is_lt(),
        _ => true,
    }
}
