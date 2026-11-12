//! Presentation over the signed local skill use cases.
mod state;
mod view;
use irmind_app::{CancellationToken, CompiledSkill, Engine, SkillOrigin};
use ratatui::{Terminal, backend::Backend};
use state::{Action, Screen, State};
use std::fmt::Write as _;
use std::{collections::BTreeSet, path::Path, time::Duration};
pub(crate) enum ManagerExit {
    Back,
    Palette,
    Quit,
}
pub(crate) fn run<B: Backend>(
    terminal: &mut Terminal<B>,
    engine: &Engine<'_>,
    shutdown: &CancellationToken,
    readonly: bool,
) -> anyhow::Result<ManagerExit>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let mut state = State::new(readonly);
    refresh(terminal, engine, &mut state);
    loop {
        view::draw(terminal, &state, engine)?;
        if shutdown.is_cancelled() {
            return Ok(ManagerExit::Quit);
        }
        if !crossterm::event::poll(Duration::from_millis(100))? {
            continue;
        }
        match state.event(crossterm::event::read()?) {
            Action::Back => return Ok(ManagerExit::Back),
            Action::Palette => return Ok(ManagerExit::Palette),
            Action::Quit => return Ok(ManagerExit::Quit),
            Action::None => {}
            Action::Inspect => {
                match background(terminal, engine, &state, || inspect(engine, &state)) {
                    Ok(preview) => {
                        state.preview = preview;
                        state.scroll = 0;
                        state.screen = Screen::Inspect;
                    }
                    Err(error) => state.notice = format!("{error}. Retry or return with Esc."),
                }
            }
            Action::Prepare => match background(terminal, engine, &state, || {
                prepare(engine, &state.path, shutdown)
            }) {
                Ok((candidate, preview)) => {
                    state.candidate = Some(candidate);
                    state.preview = preview;
                    state.screen = Screen::Review;
                    state.scroll = 0;
                    state.option = 0;
                }
                Err(error) => {
                    state.notice =
                        format!("{error}. Correct the folder and retry; your form is preserved.");
                }
            },
            Action::Apply => match background(terminal, engine, &state, || apply(engine, &state)) {
                Ok(()) => {
                    state.screen = Screen::List;
                    state.notice =
                        "Skill state applied. The next load uses the approved version.".into();
                    state.candidate = None;
                    refresh(terminal, engine, &mut state);
                }
                Err(error) => {
                    state.notice = format!(
                        "{error}. Retry or explicitly restore the approved file; your form is preserved."
                    );
                }
            },
        }
    }
}
fn refresh<B: Backend>(terminal: &mut Terminal<B>, engine: &Engine<'_>, state: &mut State)
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    match background(terminal, engine, state, || {
        engine.installed_skill_statuses().map_err(Into::into)
    }) {
        Ok(rows) => state.rows = rows,
        Err(error) => {
            state.notice = format!(
                "Skills unavailable: {error}. Check the selected keystore and retry /skills."
            );
        }
    }
}
fn prepare(
    engine: &Engine<'_>,
    directory: &str,
    cancel: &CancellationToken,
) -> anyhow::Result<(CompiledSkill, String)> {
    let services = engine
        .skill_services()
        .ok_or_else(|| anyhow::anyhow!("skill signing services are unavailable"))?;
    let candidate = engine.preview_skill(
        services.package_store(),
        services.compiler(),
        Path::new(directory),
        cancel,
    )?;
    let preview = describe(engine, &candidate)?;
    Ok((
        candidate,
        format!(
            "Sign installation or replacement? Active names and descriptions are advertised to the configured model; full content is sent only when loaded.\n{preview}"
        ),
    ))
}
fn describe(engine: &Engine<'_>, candidate: &CompiledSkill) -> anyhow::Result<String> {
    let mut text = format!(
        "{} · {}\nSHA-256: {}\nTools: {}\n",
        candidate.metadata().name().as_str(),
        candidate.metadata().version().as_str(),
        irmind_app::hex(candidate.package().hash().as_bytes()),
        candidate
            .metadata()
            .tools()
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    );
    for resource in candidate.package().resources().values() {
        let _ = write!(
            text,
            "\nResource: {}\n{}\n",
            resource.path().as_str(),
            engine.guard.screen(resource.untrusted_text())?.text
        );
    }
    Ok(text)
}
fn inspect(engine: &Engine<'_>, state: &State) -> anyhow::Result<String> {
    let row = state
        .rows
        .get(state.selected)
        .ok_or_else(|| anyhow::anyhow!("select an installed skill first"))?;
    describe(engine, &engine.inspect_skill(&row.name)?)
}
fn apply(engine: &Engine<'_>, state: &State) -> anyhow::Result<()> {
    let services = engine
        .skill_services()
        .ok_or_else(|| anyhow::anyhow!("skill signing services are unavailable"))?;
    let (store, compiler) = (services.package_store(), services.compiler());
    if state.screen == Screen::Review {
        let candidate = state
            .candidate
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("preview a skill first"))?;
        let existing = engine
            .installed_skill_statuses()?
            .iter()
            .any(|s| &s.name == candidate.metadata().name());
        if existing {
            engine.update_skill(store, compiler, candidate)?;
        } else {
            let reserved = super::case::command_registry::matches("/")
                .iter()
                .map(|s| s.name.to_owned())
                .collect::<BTreeSet<_>>();
            engine.install_skill(store, compiler, candidate, SkillOrigin::Analyst, &reserved)?;
        }
        return Ok(());
    }
    let row = state
        .rows
        .get(state.selected)
        .ok_or_else(|| anyhow::anyhow!("select a skill first"))?;
    if state.action == 3 {
        engine.restore_skill(store, compiler, &row.name)?;
    } else if row.origin == SkillOrigin::Bundled {
        engine.set_bundled_skill_active(&row.name, !row.active)?;
    } else {
        engine.set_skill_active(store, compiler, &row.name, !row.active)?;
    }
    Ok(())
}
fn background<T: Send, B: Backend>(
    terminal: &mut Terminal<B>,
    engine: &Engine<'_>,
    state: &State,
    operation: impl FnOnce() -> anyhow::Result<T> + Send,
) -> anyhow::Result<T>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    std::thread::scope(|scope| {
        let worker = scope.spawn(operation);
        while !worker.is_finished() {
            view::draw(terminal, state, engine)?;
            std::thread::sleep(Duration::from_millis(50));
        }
        worker
            .join()
            .map_err(|_| anyhow::anyhow!("skill task stopped unexpectedly"))?
    })
}
