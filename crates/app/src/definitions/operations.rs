use super::{
    ApprovedDefinitions, DefinitionCompiler, Engine, MAX_DEFINITION_BYTES, PREFIX,
    ParserDefinitionStore, Snapshot, invalid, validate_snapshot,
};
use crate::{AppError, hex, sha256};
use std::sync::Arc;

impl Engine<'_> {
    pub fn clean_definition_temporary(
        &self,
        store: &dyn ParserDefinitionStore,
    ) -> Result<usize, AppError> {
        let _lock = self.audit_log.lock_global_operations()?;
        store.clean_temporary()
    }

    pub fn approved_definitions(&self) -> Result<ApprovedDefinitions, AppError> {
        let entries = self.audit_log.global_operations()?;
        self.verify_global_operation_entries(&entries)?;
        let mut approved = ApprovedDefinitions::default();
        for entry in entries {
            let Some(payload) = entry.operation.strip_prefix(PREFIX) else {
                continue;
            };
            if payload.len() > 1024 * 1024 {
                return Err(invalid());
            }
            let bytes = hex::decode(payload).map_err(|_| invalid())?;
            let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            if serde_json::to_vec(&snapshot).map_err(|_| invalid())? != bytes {
                return Err(invalid());
            }
            validate_snapshot(&snapshot)?;
            if snapshot.previous
                != approved
                    .latest
                    .get(&snapshot.id)
                    .map(|old| old.sha256.clone())
            {
                return Err(invalid());
            }
            let snapshot = Arc::new(snapshot);
            approved.versions.insert(
                (snapshot.id.clone(), snapshot.version.clone()),
                snapshot.clone(),
            );
            approved.latest.insert(snapshot.id.clone(), snapshot);
            if approved.latest.len() > 256
                || approved.versions.len() > 4096
                || approved.latest.values().filter(|item| item.active).count() > 64
            {
                return Err(invalid());
            }
        }
        Ok(approved)
    }

    pub fn install_parser_definition(
        &self,
        store: &dyn ParserDefinitionStore,
        compiler: &dyn DefinitionCompiler,
        contents: &str,
    ) -> Result<String, AppError> {
        self.require_attended_analyst("install parser definition")?;
        if contents.len() > MAX_DEFINITION_BYTES {
            return Err(invalid());
        }
        let parser = compiler.compile(contents)?;
        let identity = parser.selector().identity();
        let _lock = self.audit_log.lock_global_operations()?;
        let approved = self.approved_definitions()?;
        let prior = approved.latest.get(identity.name);
        if (approved.latest.len() >= 256 && prior.is_none())
            || (approved.versions.len() >= 4096
                && !approved
                    .versions
                    .contains_key(&(identity.name.to_owned(), identity.version.to_owned())))
        {
            return Err(AppError::Fixed(crate::FixedAppError::Definition(
                super::DefinitionError::HistoryLimit,
            )));
        }
        if approved.latest.values().filter(|item| item.active).count() >= 64
            && !prior.is_some_and(|item| item.active)
        {
            return Err(AppError::Fixed(crate::FixedAppError::Definition(
                super::DefinitionError::ActiveLimit,
            )));
        }
        let snapshot = Snapshot {
            id: identity.name.to_owned(),
            version: identity.version.to_owned(),
            sha256: hex(&sha256(contents.as_bytes())),
            contents: contents.to_owned(),
            active: true,
            previous: prior.map(|item| item.sha256.clone()),
        };
        self.save_definition_snapshot(store, snapshot)
    }

    pub fn deactivate_parser_definition(
        &self,
        store: &dyn ParserDefinitionStore,
        id: &str,
    ) -> Result<(), AppError> {
        self.require_attended_analyst("deactivate parser definition")?;
        let _lock = self.audit_log.lock_global_operations()?;
        let approved = self.approved_definitions()?;
        let mut snapshot = approved
            .latest
            .get(id)
            .ok_or_else(invalid)?
            .as_ref()
            .clone();
        snapshot.previous = Some(snapshot.sha256.clone());
        snapshot.active = false;
        self.save_definition_snapshot(store, snapshot)?;
        Ok(())
    }

    pub fn restore_parser_definition(
        &self,
        store: &dyn ParserDefinitionStore,
        id: &str,
    ) -> Result<(), AppError> {
        self.require_attended_analyst("restore parser definition")?;
        let _lock = self.audit_log.lock_global_operations()?;
        let approved = self.approved_definitions()?;
        let mut snapshot = approved
            .latest
            .get(id)
            .ok_or_else(invalid)?
            .as_ref()
            .clone();
        snapshot.previous = Some(snapshot.sha256.clone());
        self.save_definition_snapshot(store, snapshot)?;
        Ok(())
    }

    fn save_definition_snapshot(
        &self,
        store: &dyn ParserDefinitionStore,
        snapshot: Snapshot,
    ) -> Result<String, AppError> {
        validate_snapshot(&snapshot)?;
        let bytes = serde_json::to_vec(&snapshot).map_err(|_| invalid())?;
        if bytes.len() > 512 * 1024 {
            return Err(invalid());
        }
        self.append_global_operation_unlocked(format!("{PREFIX}{}", hex::encode(bytes)))?;
        store.archive(&snapshot.sha256, &snapshot.contents)?;
        if snapshot.active {
            store.write_active(&snapshot.id, &snapshot.contents)?;
        } else {
            store.deactivate(&snapshot.id)?;
        }
        Ok(snapshot.id)
    }
}
