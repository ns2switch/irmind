#![allow(clippy::unwrap_used)]
use super::*;
use irmind_app::{
    AuditLog, CancellationToken, CryptoPorts, Engine, EnginePorts, LargeCaseUseCases, SignerBackend,
};
use irmind_domain::{Actor, ExecutionMode, ParquetArtifact};
use irmind_infra::{LocalExportVerifier, LocalVerifier, SystemClock};
use irmind_mod_keystore_file::FileKeystore;
use irmind_mod_parser_json::JsonParser;
use irmind_security::MandatoryGuard;
use std::{collections::BTreeMap, sync::Arc};

fn setup(root: &Path, _legacy: bool) -> (Arc<LocalStore>, Engine<'static>) {
    let store = Arc::new(open(root).unwrap());
    let backend = FileKeystore::ephemeral(root).unwrap();
    let signer = backend.create(Actor::Analyst).unwrap();
    let engine = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(
                signer.clone(),
                Arc::new(LocalVerifier::from_signer(signer.as_ref())),
            ),
            Arc::new(MandatoryGuard::new().unwrap()),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    (store, engine)
}

#[cfg(all(feature = "mapping-json-compat", feature = "mapping-journald-compat"))]
mod experimental;
