mod config;
mod registry;

pub use config::{ConfigField, Module, ModuleConfig, ModuleManifest, ModulePort};
pub use registry::ModuleRegistry;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::wildcard_imports)]
mod tests;
