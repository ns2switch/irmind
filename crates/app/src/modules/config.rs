#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ModulePort {
    Llm,
    Siem,
    Edr,
    CloudAudit,
    InternalIntel,
    ThreatIntel,
    EventParser,
}

#[derive(Clone, Copy, Debug)]
pub struct ConfigField {
    pub name: &'static str,
    pub required: bool,
    pub secret: bool,
}

#[derive(Debug)]
pub struct ModuleManifest {
    pub id: &'static str,
    pub version: &'static str,
    pub ports: &'static [ModulePort],
    pub tools: &'static [Tool],
    pub config: &'static [ConfigField],
}

#[derive(Default)]
pub struct ModuleConfig {
    values: BTreeMap<String, String>,
    secrets: BTreeMap<String, SecretString>,
}

impl ModuleConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_value(&mut self, name: &str, value: String) {
        self.values.insert(name.to_owned(), value);
    }

    pub fn insert_secret(&mut self, name: &str, value: SecretString) {
        self.secrets.insert(name.to_owned(), value);
    }

    #[must_use]
    pub fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    #[must_use]
    pub fn secret(&self, name: &str) -> Option<&SecretString> {
        self.secrets.get(name)
    }

    pub fn required_value(&self, name: &str) -> Result<&str, AppError> {
        self.value(name)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::Policy(format!("missing module setting {name}")))
    }

    pub fn required_secret(&self, name: &str) -> Result<&SecretString, AppError> {
        self.secret(name)
            .ok_or_else(|| AppError::Policy(format!("missing module secret {name}")))
    }

    fn validate(&self, manifest: &ModuleManifest) -> Result<(), AppError> {
        for field in manifest.config {
            let present = if field.secret {
                self.secrets.contains_key(field.name)
            } else {
                self.values.contains_key(field.name)
            };
            if field.required && !present {
                return Err(AppError::Policy(format!(
                    "missing module setting {}",
                    field.name
                )));
            }
        }
        for name in self.values.keys().chain(self.secrets.keys()) {
            if !manifest.config.iter().any(|field| field.name == name) {
                return Err(AppError::Policy(format!("unknown module setting {name}")));
            }
        }
        Ok(())
    }
}

pub trait Module: Send + Sync {
    fn manifest(&self) -> &'static ModuleManifest;
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        config: &ModuleConfig,
    ) -> Result<(), AppError>;
}
