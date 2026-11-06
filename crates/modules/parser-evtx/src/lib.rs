#![forbid(unsafe_code)]
mod codec;
mod input;
mod normalize;
mod strict;

use irmind_app::{
    AppError, CancellationToken, EventParser, GraphRecord, LogParser, ParseReport,
    ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::Tainted;
use irmind_process_containment::{Mode, Program};
use std::{fs::File, io::Read, path::Path, time::Duration};

pub const VERSION: &str = "evtx-0.15.1-ndjson-v1";
pub const MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-evtx",
    version: "0.1.0",
    ports: &[ModulePort::EventParser],
    tools: &[],
    config: &[],
};
pub struct EvtxParser {
    program: Option<Program>,
    issue: Option<String>,
}
fn bad(message: &'static str) -> AppError {
    AppError::Policy(message.into())
}
impl EvtxParser {
    pub fn new(helper: &Path, data_root: &Path) -> Self {
        let prepared = (|| {
            let program=Program::new(helper,data_root).map_err(|_|bad("EVTX helper is missing or its private runtime cannot be created; install the matching irmind-evtx binary and check the data directory"))?;
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
                program: Some(program),
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
            .map_or_else(Default::default, Program::witness_stats)
    }
    pub fn unavailable_reason(&self) -> Option<&str> {
        self.issue.as_deref()
    }
    fn parse_file(
        &self,
        source: &str,
        file: &File,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<irmind_app::IndexedGraphRecord>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let program=self.program.as_ref().ok_or_else(||bad("EVTX is unavailable: install its helper and enable the required operating-system isolation"))?;
        let size = file
            .metadata()
            .map_err(|_| bad("cannot inspect EVTX source"))?
            .len();
        if !(4096..=4 * 1024 * 1024 * 1024).contains(&size) {
            return Err(bad("EVTX source must be between 4 KiB and 4 GiB"));
        }
        let child = program
            .spawn_cancelable(file, Mode::Decode, &|| cancel.is_cancelled())
            .map_err(|_| if cancel.is_cancelled() { AppError::Cancelled } else { bad("cannot start the contained EVTX decoder; check BFE/MpsSvc and the verified sandbox") })?;
        let mut state = codec::State::new(source, hash, size);
        let result = input::run(
            child,
            (size.saturating_mul(32) + (1 << 20)).min(8 << 30),
            Duration::from_mins(10),
            cancel,
            &mut |bytes| state.frame(&bytes, emit),
        )
        .and_then(|()| state.finish());
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
impl EventParser for EvtxParser {
    fn version(&self) -> &'static str {
        VERSION
    }
    fn parse_each(
        &self,
        _: &str,
        _: &[u8],
        cancel: &CancellationToken,
        _: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        Err(bad(
            "EVTX requires the authenticated seekable-file ingestion route",
        ))
    }
}
impl StreamingEventParser for EvtxParser {
    fn parser_name(&self) -> &'static str {
        "parser-evtx"
    }
    fn streaming_version(&self) -> &'static str {
        VERSION
    }
    fn partition_profile(&self, _: &GraphRecord) -> irmind_app::PartitionProfile {
        irmind_app::PartitionProfile::EndpointHost
    }
    fn prefers_local_file(&self, _: &str, sample: &[u8]) -> bool {
        codec::detect(sample)
    }
    fn parse_reader(
        &self,
        _: &str,
        _: &mut dyn Read,
        _: [u8; 32],
        cancel: &CancellationToken,
        _: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        Err(bad(
            "EVTX requires an authenticated seekable file; remote objects use the private case spool",
        ))
    }
    fn parse_local_file_report(
        &self,
        source: &str,
        file: &mut File,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        self.parse_file(source, file, hash, cancel, &mut |row| {
            let mut record = None;
            row.inspect(|r| record = Some(r.record.clone()));
            emit(Tainted::from_external(
                record.ok_or_else(|| bad("EVTX record missing"))?,
                row.provenance().clone(),
            ))
        })
    }
    fn parse_indexed_local_file_report(
        &self,
        source: &str,
        file: &mut File,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<irmind_app::IndexedGraphRecord>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        self.parse_file(source, file, hash, cancel, emit)
    }
}

#[cfg(feature = "fuzzing")]
pub fn fuzz_protocol(bytes: &[u8]) {
    irmind_process_containment::fuzz_witness_protocol(bytes);
    let _ = strict::decode(bytes);
    let _ = codec::detect(bytes);
    let mut state = codec::State::new("synthetic.evtx", [0; 32], 69632);
    for line in bytes.split(|byte| *byte == b'\n').take(128) {
        let _ = state.frame(line, &mut |_| Ok(()));
    }
    let _ = state.finish();
}
#[cfg(test)]
mod tests;
