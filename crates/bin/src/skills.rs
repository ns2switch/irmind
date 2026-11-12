//! Composition of local methodology capabilities; no remote source is enabled.
use anyhow::{Result, anyhow};
use irmind_app::SignerBackend;
use std::{path::Path, sync::Arc};

pub(super) fn agent(backend: &dyn SignerBackend) -> Result<Arc<dyn irmind_app::Signer>> {
    let actor = irmind_domain::Actor::Agent(
        irmind_domain::AgentId::parse("skills-agent")
            .map_err(|_| anyhow!("invalid built-in agent identity"))?,
    );
    // create refuses replacement, including when load failed for another reason.
    backend
        .load(actor.clone())
        .or_else(|_| backend.create(actor))
        .map_err(Into::into)
}

pub(super) fn services(
    home: &Path,
    agent: Arc<dyn irmind_app::Signer>,
) -> Result<irmind_app::SkillServices> {
    let store = irmind_infra::FileSkillPackageStore::new(home);
    let removed = irmind_app::SkillPackageStore::clean_temporary(&store)?;
    if removed > 0 {
        tracing::info!(removed, "removed interrupted skill publication files");
    }
    Ok(irmind_app::SkillServices::new(
        Arc::new(store),
        Arc::new(irmind_infra::TomlSkillCompiler),
        agent,
        irmind_infra::bundled_skill_candidates()?
            .into_iter()
            .map(|skill| skill.package().clone())
            .collect(),
    )?)
}
