#![forbid(unsafe_code)]
mod codec;
mod input;
mod source_decode;
mod strict;
pub use source_decode::{SOURCE_VERSION, detect_source};

use irmind_app::{
    AppError, CancellationToken, LogParser, ParseReport, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_process_containment::{Mode, Program};
use std::{fs::File, path::Path, sync::Arc, time::Duration};

pub const VERSION: &str = "evtx-0.15.1-ndjson-v1";
pub const MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-evtx",
    version: "0.1.0",
    ports: &[ModulePort::EventParser, ModulePort::SourceDecoder],
    tools: &[],
    config: &[],
};
#[derive(Clone)]
pub struct EvtxParser {
    program: Option<Arc<Program>>,
    issue: Option<String>,
}
fn bad(message: &'static str) -> AppError {
    AppError::Policy(message.into())
}
fn initialization_error(error: &std::io::Error) -> AppError {
    AppError::Policy(format!(
        "EVTX helper/runtime initialization failed ({error}); install the matching irmind-evtx binary, check the data directory, and on Windows check BFE/MpsSvc service availability"
    ))
}
impl EvtxParser {
    pub fn new(helper: &Path, data_root: &Path) -> Self {
        let prepared = (|| {
            let program =
                Program::new(helper, data_root).map_err(|error| initialization_error(&error))?;
            let mut probe = false;
            let child = program.probe().map_err(|error| {
                AppError::Policy(format!("EVTX native containment cannot start ({error}); check the helper installation and platform sandbox requirements"))
            })?;
            input::run(
                child,
                4096,
                Duration::from_secs(10),
                &CancellationToken::new(),
                &mut |bytes| {
                    codec::probe(&bytes)?;
                    if probe {
                        return Err(bad("duplicate EVTX isolation response"));
                    }
                    probe = true;
                    Ok(())
                },
            )?;
            if !probe {
                return Err(bad(
                    "EVTX isolation was not verified; check Landlock/seccomp or the native platform sandbox",
                ));
            }
            Ok(program)
        })();
        match prepared {
            Ok(program) => Self {
                program: Some(Arc::new(program)),
                issue: None,
            },
            Err(error) => Self {
                program: None,
                issue: Some(error.to_string()),
            },
        }
    }
    pub fn witness_stats(&self) -> irmind_process_containment::WitnessStats {
        self.program
            .as_ref()
            .map_or_else(Default::default, |program| program.witness_stats())
    }
    pub fn unavailable_reason(&self) -> Option<&str> {
        self.issue.as_deref()
    }
    fn completed(&self, result: Result<ParseReport, AppError>) -> Result<ParseReport, AppError> {
        if result.is_err()
            && let Some(program) = &self.program
        {
            program.invalidate();
        }
        result
    }
    fn decode_file_workers(
        &self,
        file: &File,
        cancel: &CancellationToken,
        workers: usize,
        frame: &mut dyn FnMut(&[u8]) -> Result<(), AppError>,
    ) -> Result<(), AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let program=self.program.as_ref().ok_or_else(||bad("EVTX is unavailable: install its helper and enable the required operating-system isolation"))?;
        let size = file
            .metadata()
            .map_err(|_| bad("cannot inspect EVTX source"))?
            .len();
        if !(4096..=4 * 1024 * 1024 * 1024).contains(&size) {
            return Err(bad(
                "EVTX source size limit reached (4096 to 4294967296 bytes); entire file rejected; no partial ingestion",
            ));
        }
        let child = program
            .spawn_cancelable(file, Mode::DecodeParallel(std::num::NonZeroU8::new(u8::try_from(workers.min(64)).map_err(|_| bad("invalid EVTX worker budget"))?).ok_or_else(|| bad("invalid EVTX worker budget"))?), &|| cancel.is_cancelled())
            .map_err(|_| if cancel.is_cancelled() { AppError::Cancelled } else { bad("cannot start the contained EVTX decoder; check BFE/MpsSvc and the verified sandbox") })?;
        let result = input::run(
            child,
            (size.saturating_mul(32) + (1 << 20)).min(8 << 30),
            Duration::from_mins(10),
            cancel,
            &mut |bytes| frame(&bytes),
        );
        if result.is_err() {
            program.invalidate();
        }
        result
    }
}
impl Module for EvtxParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(Arc::new((*self).clone()))?;
        registry.add_parser(self)
    }
}
impl LogParser for EvtxParser {
    fn detect(&self, _: &str, sample: &[u8]) -> Option<ParserConfidence> {
        if !codec::detect(sample) {
            return None;
        }
        ParserConfidence::new(95).ok()
    }
}

impl StreamingEventParser for EvtxParser {
    fn source_parallelism(&self, _: &str) -> Result<irmind_app::SourceParallelism, AppError> {
        Ok(if cfg!(windows) {
            irmind_app::SourceParallelism::Serial
        } else {
            irmind_app::SourceParallelism::Concurrent
        })
    }

    fn parser_name(&self) -> &'static str {
        "parser-evtx"
    }
    fn streaming_version(&self) -> &'static str {
        VERSION
    }
    fn prefers_local_file(&self, _: &str, sample: &[u8]) -> bool {
        codec::detect(sample)
    }
}

#[cfg(feature = "fuzzing")]
pub fn fuzz_protocol(bytes: &[u8]) {
    irmind_process_containment::fuzz_witness_protocol(bytes);
    source_decode::fuzz(bytes);
    let _ = strict::decode(bytes);
    let _ = codec::detect(bytes);
}
#[cfg(test)]
mod tests;
