//! Presentation for the application's signed declarative-definition use cases.
use crate::{WorkspaceIo, theme::Theme};
use anyhow::{Result, anyhow};
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use irmind_app::{CancellationToken, DefinitionStatus, Engine};
use ratatui::{Terminal, backend::Backend};
use std::{path::Path, time::Duration};

mod state;
mod view;
use state::{Action, State};

pub(crate) enum ManagerExit {
    Back,
    Palette,
    Restart,
    Quit,
}

pub(crate) fn run<B: Backend>(
    terminal: &mut Terminal<B>,
    engine: &Engine<'_>,
    io: &dyn WorkspaceIo,
    shutdown: &CancellationToken,
    command: &str,
) -> Result<ManagerExit>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let mut state = State::new(command);
    state.statuses = background(terminal, engine, &state, || statuses(engine, io))?;
    loop {
        view::draw(terminal, &state, engine)?;
        if shutdown.is_cancelled() {
            return Ok(ManagerExit::Quit);
        }
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        let action = state.event(event::read()?);
        match action {
            Action::None => {}
            Action::Back => return Ok(ManagerExit::Back),
            Action::Palette => return Ok(ManagerExit::Palette),
            Action::Quit => return Ok(ManagerExit::Quit),
            Action::Preview | Action::PrepareInstall => {
                let result = background(terminal, engine, &state, || {
                    prepare(engine, io, &state, action)
                });
                state.prepared(result, action);
            }
            Action::Install | Action::Deactivate | Action::Restore => {
                let result = background(terminal, engine, &state, || {
                    change(engine, io, &state, action)
                });
                match result {
                    Ok(()) => return Ok(ManagerExit::Restart),
                    Err(error) => {
                        state.notice = format!(
                            "Not applied: {error}. Correct the problem and retry; the form is preserved."
                        );
                    }
                }
            }
        }
    }
}

fn statuses(engine: &Engine<'_>, io: &dyn WorkspaceIo) -> Result<Vec<DefinitionStatus>> {
    let (store, compiler) = ports(io)?;
    Ok(engine
        .approved_definitions()?
        .load_active(store, compiler)
        .1)
}

fn ports(
    io: &dyn WorkspaceIo,
) -> Result<(
    &dyn irmind_app::ParserDefinitionStore,
    &dyn irmind_app::DefinitionCompiler,
)> {
    Ok((
        io.definition_store()
            .ok_or_else(|| anyhow!("definition storage is unavailable"))?,
        io.definition_compiler()
            .ok_or_else(|| anyhow!("this binary was built without parser-declarative"))?,
    ))
}

fn prepare(
    engine: &Engine<'_>,
    io: &dyn WorkspaceIo,
    state: &State,
    action: Action,
) -> Result<(String, String)> {
    let (_, compiler) = ports(io)?;
    let bytes = io.read_parser_input(
        Path::new(&state.fields[0]),
        irmind_app::MAX_DEFINITION_BYTES,
    )?;
    let contents =
        String::from_utf8(bytes).map_err(|_| anyhow!("definition must be UTF-8 TOML"))?;
    let parser = compiler.compile(&contents)?;
    let identity = parser.identity();
    let preview = if action == Action::Preview {
        let sample = io.read_parser_input(Path::new(&state.fields[1]), 1024 * 1024)?;
        engine.preview_parser_definition(compiler, &contents, &sample)?
    } else {
        format!(
            "Install {}?\nVersion: {}\nSHA-256: {}\n{}\nThis signs the complete definition in the global operational chain. The parser runs locally and grants no permissions. The session restarts after applying.",
            identity.name,
            identity.version,
            irmind_app::hex(&irmind_app::sha256(contents.as_bytes())),
            parser.description()
        )
    };
    Ok((contents, preview))
}

fn change(engine: &Engine<'_>, io: &dyn WorkspaceIo, state: &State, action: Action) -> Result<()> {
    let (store, compiler) = ports(io)?;
    match action {
        Action::Install => {
            engine.install_parser_definition(store, compiler, &state.contents)?;
        }
        Action::Deactivate => engine.deactivate_parser_definition(store, &state.selected_id())?,
        Action::Restore => engine.restore_parser_definition(store, &state.selected_id())?,
        _ => return Err(anyhow!("invalid definition action")),
    }
    Ok(())
}

/// Filesystem, compilation and signing run away from the rendering thread.
fn background<T: Send, B: Backend>(
    terminal: &mut Terminal<B>,
    engine: &Engine<'_>,
    state: &State,
    operation: impl FnOnce() -> Result<T> + Send,
) -> Result<T>
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
            .map_err(|_| anyhow!("definition task stopped unexpectedly"))?
    })
}
