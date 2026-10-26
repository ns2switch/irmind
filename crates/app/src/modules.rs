//! Compile-time modules are owned by the composition root and exposed through application ports.

use crate::{
    AppError, CloudAuditPort, EdrPort, Engine, EventParser, InternalIntelPort, LlmPort, SiemPort,
    ThreatIntelPort, hex, sha256,
};
use irmind_domain::Tool;
use secrecy::SecretString;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

include!("modules/config.rs");
include!("modules/registry.rs");
include!("modules/tests.rs");
