use anyhow::Result;

use crate::TerminalSession;

mod wizard;
pub use wizard::{KeystoreWizard, run_keystore_wizard};
pub(crate) use wizard::{prompt_secret, render};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeystoreChoice {
    pub signer: &'static str,
    pub secrets: &'static str,
}

impl KeystoreChoice {
    pub fn initial(os_available: bool, file_compiled: bool) -> Result<Self> {
        let backend = if os_available {
            "os"
        } else if file_compiled {
            "file"
        } else {
            anyhow::bail!("no usable keystore backend is available");
        };
        Ok(Self {
            signer: backend,
            secrets: backend,
        })
    }
}
