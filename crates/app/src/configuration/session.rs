use super::{ConfigChange, ConfigurationStore, ModuleManifest, invalid};
use crate::{AppError, Engine, hex};

impl Engine<'_> {
    pub fn record_session_overrides(
        &self,
        store: &dyn ConfigurationStore,
        manifests: &[&ModuleManifest],
        changes: &[ConfigChange],
    ) -> Result<(), AppError> {
        self.require_attended_analyst("activate session overrides")?;
        if changes.is_empty() || changes.len() > 64 {
            return Err(invalid());
        }
        let _lock = self.audit_log.lock_global_operations()?;
        self.verify_configuration(store, manifests)?;
        let saved = store.load()?;
        let mut effective = saved.clone();
        for change in changes {
            effective = effective.changed(change.clone(), manifests)?;
        }
        let bytes = serde_json::to_vec(changes).map_err(|_| invalid())?;
        if bytes.len() > 65_536 {
            return Err(invalid());
        }
        self.append_global_operation_unlocked(format!(
            "session-overrides-v1:{}:{}:{}",
            saved.fingerprint()?,
            effective.fingerprint()?,
            hex(&bytes)
        ))?;
        Ok(())
    }
}
