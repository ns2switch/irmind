use super::state::SourceKind;
use super::{Candidate, Screen, State};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use irmind_app::{CancellationToken, Engine, SkillOrigin};
use ratatui::{Terminal, backend::Backend};
use std::{fmt::Write as _, time::Duration};
pub(super) fn initial_command(state: &mut State, command: &str) {
    if command == "/skills" {
        return;
    }
    if state.readonly {
        state.notice = "Demo methods are read-only; catalog downloads are disabled.".into();
        return;
    }
    if let Some(selection) = command.strip_prefix("/skills install ") {
        if selection.is_empty() || selection.len() > 4096 {
            state.notice = "Enter a bounded folder or catalog:name selection.".into();
            return;
        }
        if let Some(selection) = selection.strip_prefix("catalog:") {
            let (name, tag) = selection.rsplit_once('@').unwrap_or((selection, ""));
            state.catalog_name = name.into();
            state.catalog_tag = tag.into();
            state.source = SourceKind::Catalog;
            state.screen = Screen::Catalog;
        } else {
            state.path = selection.into();
            state.source = SourceKind::Local;
            state.screen = Screen::Path;
        }
    } else if let Some(name) = command.strip_prefix("/skills update ") {
        let Some((index, row)) = state
            .rows
            .iter()
            .enumerate()
            .find(|(_, row)| row.name.as_str() == name)
        else {
            state.notice = "Select an installed skill to update.".into();
            return;
        };
        state.selected = index;
        if row.origin == SkillOrigin::Catalog {
            state.catalog_name = name.into();
            state.catalog_tag.clear();
            state.source = SourceKind::Catalog;
            state.screen = Screen::Catalog;
        } else {
            state.path.clear();
            state.source = SourceKind::Local;
            state.screen = Screen::Path;
        }
    } else {
        state.notice = "Use /skills install catalog:<name> or /skills update <name>.".into();
    }
}
pub(super) fn prepare_catalog(
    engine: &Engine<'_>,
    name: &str,
    tag: &str,
    cancel: &CancellationToken,
) -> anyhow::Result<(Candidate, String)> {
    let tag = (!tag.is_empty()).then_some(tag);
    let preview = engine.configured_catalog_preview(
        name,
        tag,
        &crate::case::command_registry::reserved_names(),
        cancel,
    )?;
    catalog_preview(engine, preview)
}
fn catalog_preview(
    engine: &Engine<'_>,
    preview: irmind_app::catalog::CatalogInstallPreview,
) -> anyhow::Result<(Candidate, String)> {
    let mut text = super::describe(engine, preview.skill())?;
    let _ = write!(
        text,
        "\nPublisher index: {} · commit {} · sequence {}\nKey: {}\nUntrusted until your signed admission; no tool permissions are granted.\n\n{}",
        preview.receipt().release_tag(),
        preview.receipt().release_commit(),
        preview.receipt().sequence(),
        irmind_app::hex(preview.receipt().key_id().as_bytes()),
        preview.differences()
    );
    if preview.downgrade_confirmation_required() {
        text.insert_str(
            0,
            "Catalog or package downgrade: separate confirmation is required before signing.\n\n",
        );
    }
    Ok((Candidate::Catalog(Box::new(preview)), text))
}
pub(super) fn prepare_background<B: Backend>(
    terminal: &mut Terminal<B>,
    engine: &Engine<'_>,
    io: &dyn crate::WorkspaceIo,
    state: &mut State,
    shutdown: &CancellationToken,
) -> anyhow::Result<(Candidate, String)>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    if state.readonly {
        anyhow::bail!("Demo skill installations and downloads are disabled");
    }
    let path = state.path.clone();
    let name = state.catalog_name.clone();
    let tag = state.catalog_tag.clone();
    let source = state.source;
    let cancel = shutdown.child_token();
    state.notice = "Preparing the exact package preview… Esc cancels without admission.".into();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| match source {
            SourceKind::Local => super::prepare(engine, &path, &cancel),
            SourceKind::Catalog => prepare_catalog(engine, &name, &tag, &cancel),
            SourceKind::Offline => prepare_offline(engine, io, &path, &name, &tag, &cancel),
        });
        while !worker.is_finished() {
            super::view::draw(terminal, state, engine)?;
            if event::poll(Duration::from_millis(50))? {
                busy_event(state, &event::read()?, &cancel, shutdown);
            }
        }
        worker
            .join()
            .map_err(|_| anyhow::anyhow!("skill preview stopped unexpectedly"))?
    })
}
fn busy_event(
    state: &mut State,
    event: &Event,
    cancel: &CancellationToken,
    shutdown: &CancellationToken,
) {
    let Event::Key(key) = event else {
        return;
    };
    if key.kind == KeyEventKind::Release {
        return;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('k') {
        cancel.cancel();
        state.pending_exit = Some(super::ManagerExit::Palette);
    } else if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        state.confirm_exit = true;
    } else if state.confirm_exit {
        match key.code {
            KeyCode::Enter => {
                cancel.cancel();
                shutdown.cancel();
            }
            KeyCode::Esc => state.confirm_exit = false,
            _ => {}
        }
    } else if key.code == KeyCode::Esc {
        cancel.cancel();
        state.notice = "Cancelling the preview; no admission has been signed.".into();
    }
}
fn prepare_offline(
    engine: &Engine<'_>,
    io: &dyn crate::WorkspaceIo,
    folder: &str,
    name: &str,
    tag: &str,
    cancel: &CancellationToken,
) -> anyhow::Result<(Candidate, String)> {
    use irmind_app::catalog::{BoundedPackageBytes, CatalogIndexBytes, FrozenCatalogRelease};
    irmind_app::SkillName::parse(name)?;
    let release = FrozenCatalogRelease::new(tag)?;
    let root = std::path::Path::new(folder);
    if cancel.is_cancelled() {
        anyhow::bail!("Preview cancelled");
    }
    // Reuse the existing bounded no-follow presentation reader; no source port,
    // network client or evidence ingestion is involved in offline import.
    let index = io.read_parser_input(&root.join("index.json"), 1024 * 1024)?;
    let signature = io.read_parser_input(&root.join("index.ed25519"), 64)?;
    let raw = CatalogIndexBytes::new(index, &signature)?;
    let verified = engine.verify_offline_catalog_index(&raw, &release)?;
    let asset = verified.asset(name)?;
    if cancel.is_cancelled() {
        anyhow::bail!("Preview cancelled");
    }
    let package = BoundedPackageBytes::new(
        io.read_parser_input(&root.join(asset.entry().asset()), 1024 * 1024)?,
    )?;
    let preview = engine.preview_catalog_offline(
        &raw,
        &release,
        &package,
        (name, env!("CARGO_PKG_VERSION")),
        &crate::case::command_registry::reserved_names(),
        cancel,
    )?;
    catalog_preview(engine, preview)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEvent;
    #[test]
    fn catalog_commands_prefill_literal_forms_without_starting_downloads_in_demo() {
        let mut state = State::new(false);
        initial_command(
            &mut state,
            "/skills install catalog:community-triage@v1.2.3",
        );
        assert!(state.screen == Screen::Catalog);
        assert_eq!(state.catalog_name, "community-triage");
        assert_eq!(state.catalog_tag, "v1.2.3");
        let mut demo = State::new(true);
        initial_command(&mut demo, "/skills install catalog:community-triage");
        assert!(demo.screen == Screen::List);
        assert!(demo.path.is_empty());
    }
    #[test]
    fn busy_preview_can_cancel_and_exit_requires_confirmation() {
        let mut state = State::new(false);
        let cancel = CancellationToken::new();
        let shutdown = CancellationToken::new();
        busy_event(
            &mut state,
            &Event::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            &cancel,
            &shutdown,
        );
        assert!(state.confirm_exit);
        assert!(!shutdown.is_cancelled());
        busy_event(
            &mut state,
            &Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            &cancel,
            &shutdown,
        );
        assert!(!state.confirm_exit);
        assert!(!cancel.is_cancelled());
        busy_event(
            &mut state,
            &Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            &cancel,
            &shutdown,
        );
        assert!(cancel.is_cancelled());
        assert!(!shutdown.is_cancelled());
    }
}
