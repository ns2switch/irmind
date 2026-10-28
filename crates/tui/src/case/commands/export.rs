use super::super::{Confirmation, confirmation_summary};
use super::CaseRuntime;
use anyhow::{Result, bail};
use irmind_app::CaseId;
use std::path::PathBuf;

pub(super) struct ExportRequest {
    pub path: PathBuf,
    pub source_root: Option<PathBuf>,
    pub include_originals: bool,
}

pub(super) fn parse_export_request(prompt: &str, id: &CaseId) -> Result<ExportRequest> {
    let default_path = || PathBuf::from(format!("{}.irmind.json", id.as_str()));
    if prompt == "/export" {
        return Ok(ExportRequest {
            path: default_path(),
            source_root: None,
            include_originals: false,
        });
    }
    if let Some(root) = prompt.strip_prefix("/export --with-originals") {
        let Some(root) = root
            .strip_prefix(' ')
            .filter(|value| !value.trim().is_empty())
        else {
            bail!("use /export --with-originals <source-root>");
        };
        return Ok(ExportRequest {
            path: default_path(),
            source_root: Some(PathBuf::from(root)),
            include_originals: true,
        });
    }
    let Some(path) = prompt
        .strip_prefix("/export ")
        .filter(|value| !value.trim().is_empty())
    else {
        bail!("use /export [destination]");
    };
    Ok(ExportRequest {
        path: PathBuf::from(path),
        source_root: None,
        include_originals: false,
    })
}

impl CaseRuntime<'_, '_, '_> {
    pub(super) fn seal_or_export_command(&mut self, prompt: &str) -> Result<bool> {
        if prompt == "/seal" {
            if let Some(Confirmation::Seal(preview, _)) = self.state.confirmed_action.take() {
                let workflow = self.workflow();
                self.start_task("Seal", move |cancel| {
                    if cancel.is_cancelled() {
                        return Err(irmind_app::AppError::Cancelled);
                    }
                    workflow.seal_prepared(&preview)?;
                    Ok("Case sealed".into())
                });
            } else {
                let workflow = self.workflow();
                let id = self.id;
                let sender = self.seal_tx.clone();
                self.start_task("Prepare seal", move |cancel| {
                    let preview = workflow.prepare_seal(id, &cancel)?;
                    sender.send(preview).map_err(|_| {
                        irmind_app::AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                            irmind_app::AdapterStorageError::SealPreviewUIUnavailable,
                        ))
                    })?;
                    Ok("review the signed preview".into())
                });
            }
            return Ok(true);
        }
        if prompt == "/export" || prompt.starts_with("/export ") {
            let request = parse_export_request(prompt, self.id)?;
            if let Some(Confirmation::Export(approved, _)) = self.state.confirmed_action.take()
                && approved == prompt
            {
                let workflow = self.workflow();
                let id = self.id;
                self.start_task("Export", move |cancel| {
                    if cancel.is_cancelled() {
                        return Err(irmind_app::AppError::Cancelled);
                    }
                    workflow
                        .export_with_options(
                            id,
                            &request.path,
                            request.source_root.as_deref(),
                            request.include_originals,
                            &cancel,
                        )
                        .map(|fingerprint| format!("Exported case; analyst key {fingerprint}"))
                });
            } else {
                let summary = confirmation_summary(self.engine, self.id, "Export")?;
                let originals = request.source_root.as_ref().map_or_else(
                    || "Originals: omitted; signed manifest only".into(),
                    |root| format!("Originals: include from {}", root.display()),
                );
                self.state.confirmation = Some(Confirmation::Export(
                    prompt.to_owned(),
                    format!(
                        "{summary}\nDestination: {}\n{originals}",
                        request.path.display()
                    ),
                ));
            }
            return Ok(true);
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::parse_export_request;
    use irmind_app::CaseId;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn explicit_originals_require_a_root_and_use_the_default_destination() {
        let id = CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
        assert!(parse_export_request("/export --with-originals", &id).is_err());
        let request =
            parse_export_request("/export --with-originals synthetic-sources", &id).unwrap();
        assert!(request.include_originals);
        assert_eq!(
            request
                .source_root
                .as_deref()
                .and_then(std::path::Path::to_str),
            Some("synthetic-sources")
        );
        assert_eq!(
            request.path.to_str(),
            Some("11111111-1111-1111-1111-111111111111.irmind.json")
        );
    }
}
