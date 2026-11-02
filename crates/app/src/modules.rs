mod config;
mod parsers;
mod registry;

pub use config::{ConfigField, Module, ModuleConfig, ModuleManifest, ModulePort};
pub use parsers::{DetectedParser, ParserCatalog, ParserChoice, ParserResolver, RebuildParser};
pub use registry::ModuleRegistry;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::wildcard_imports)]
mod tests;
