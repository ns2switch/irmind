#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MappingError {
    InvalidManifest,
    InvalidDefinition,
    InvalidOutput,
    UnsupportedSourceValue,
    UnsupportedDecoder,
    DuplicateIdentity,
    UnsupportedVersion,
    Capacity {
        limit: usize,
        count: usize,
        decoder: Option<(String, String)>,
        modules: std::collections::BTreeMap<String, usize>,
    },
    Overlap {
        first: String,
        second: String,
        selector: String,
    },
    Ambiguous {
        first: String,
        second: String,
    },
}

impl std::fmt::Display for MappingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidManifest => f.write_str("mapping manifest is invalid"),
            Self::InvalidDefinition => f.write_str("mapping definition is invalid"),
            Self::InvalidOutput => f.write_str("mapping output does not match the decoded source"),
            Self::UnsupportedSourceValue => {
                f.write_str("source values are not supported by this mapping")
            }
            Self::UnsupportedDecoder => f.write_str("the exact source decoder is unavailable"),
            Self::DuplicateIdentity => f.write_str("mapping catalog contains a duplicate identity"),
            Self::UnsupportedVersion => {
                f.write_str("mapping selects an unregistered decoder version")
            }
            Self::Capacity {
                limit,
                count,
                decoder,
                modules,
            } => {
                write!(
                    f,
                    "mapping limit exceeded ({count} mappings, limit {limit})"
                )?;
                if let Some((name, version)) = decoder {
                    write!(f, " for decoder {name} {version}")?;
                }
                f.write_str(". Contributions by mapping module")?;
                for (module, count) in modules {
                    write!(f, " {module}={count}")?;
                }
                Ok(())
            }
            Self::Overlap {
                first,
                second,
                selector,
            } => {
                write!(f, "mappings {first} and {second} overlap at {selector}")
            }
            Self::Ambiguous { first, second } => {
                write!(
                    f,
                    "record matches both {first} and {second}; mapping selection is ambiguous"
                )
            }
        }
    }
}
impl std::error::Error for MappingError {}
