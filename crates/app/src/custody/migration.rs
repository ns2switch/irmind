use crate::{
    Actor, AppError, CancellationToken, CancelledOperation, CaseId, Engine, GLOBAL_OPERATION_SCOPE,
    SecretBackend, SignedOperation, SignerBackend, sha256,
};
use secrecy::ExposeSecret as _;
use std::collections::BTreeMap;

impl Engine<'_> {
    pub fn migrate_signer_backend(
        &self,
        source: &dyn SignerBackend,
        target: &dyn SignerBackend,
    ) -> Result<(), AppError> {
        self.require_attended_analyst("migrate signing key")?;
        let old_key = source.public_key_for_actor(&Actor::Analyst)?;
        if old_key != self.signer.public_key() || source.manifest().id == target.manifest().id {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyInvalidSigningBackendMigration,
            ));
        }
        let cases = self.repo.list_cases()?;
        for case in &cases {
            self.verify(&case.id)?;
        }
        let mut actors = BTreeMap::from([(Actor::Analyst.as_storage(), Actor::Analyst)]);
        for case in &cases {
            for actor in self
                .audit_log
                .entries(&case.id)?
                .into_iter()
                .map(|entry| entry.actor)
                .chain(
                    self.audit_log
                        .operations(&case.id)?
                        .into_iter()
                        .map(|entry| entry.actor),
                )
            {
                actors.insert(actor.as_storage(), actor);
            }
        }
        let mut ordered = vec![Actor::Analyst];
        ordered.extend(
            actors
                .into_values()
                .filter(|actor| *actor != Actor::Analyst),
        );
        for actor in ordered {
            let original = source.public_key_for_actor(&actor)?;
            match target.public_key_for_actor(&actor) {
                Ok(existing) if existing == original => continue,
                Ok(_) => {
                    return Err(AppError::Fixed(
                        crate::FixedAppError::SignatureDestinationHasADifferentSigningKey,
                    ));
                }
                Err(_) => {}
            }
            let recipient = target.migration_recipient(&actor)?;
            let packet = source.export_wrapped(&actor, &recipient)?;
            target.import_wrapped(actor.clone(), &packet)?;
            if target.public_key_for_actor(&actor)? != original {
                return Err(AppError::Fixed(
                    crate::FixedAppError::SignatureMigratedSigningFingerprintDiffers,
                ));
            }
        }
        self.record_global_keystore_migration("signer", source.manifest().id, target.manifest().id)
    }

    pub fn migrate_secret_backend(
        &self,
        source: &dyn SecretBackend,
        target: &dyn SecretBackend,
        fields: &[&str],
    ) -> Result<(), AppError> {
        self.require_attended_analyst("migrate module credentials")?;
        if source.manifest().id == target.manifest().id {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyInvalidSecretBackendMigration,
            ));
        }
        let cases = self.repo.list_cases()?;
        for case in &cases {
            self.verify(&case.id)?;
        }
        for field in fields {
            match source.get(field) {
                Ok(value) => {
                    target.put(field, &value)?;
                    if target.get(field)?.expose_secret() != value.expose_secret() {
                        return Err(AppError::Fixed(
                            crate::FixedAppError::StorageMigratedCredentialVerificationFailed,
                        ));
                    }
                }
                Err(AppError::SecretMissing) => {}
                Err(error) => return Err(error),
            }
        }
        self.record_global_keystore_migration("secrets", source.manifest().id, target.manifest().id)
    }

    pub fn record_cancellation(
        &self,
        id: &CaseId,
        operation: CancelledOperation,
    ) -> Result<(), AppError> {
        self.record_operational_event(id, operation.as_str())
    }

    fn record_global_keystore_migration(
        &self,
        capability: &str,
        from: &str,
        to: &str,
    ) -> Result<(), AppError> {
        self.require_attended_analyst("migrate keystore")?;
        if !matches!(capability, "signer" | "secrets")
            || !matches!(from, "os" | "file")
            || !matches!(to, "os" | "file")
            || from == to
        {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyInvalidKeystoreMigration,
            ));
        }
        let _global_lock = self.audit_log.lock_global_operations()?;
        self.verify_global_operations()?;
        let last = self.audit_log.global_operations()?.pop();
        let mut entry = SignedOperation {
            case_id: GLOBAL_OPERATION_SCOPE.into(),
            seq: last.as_ref().map_or(Ok(1), |previous| {
                previous.seq.checked_add(1).ok_or({
                    AppError::Fixed(
                        crate::FixedAppError::PolicyGlobalOperationalAuditSequenceExhausted,
                    )
                })
            })?,
            at: self.clock.now()?,
            actor: Actor::Analyst,
            operation: format!("keystore-migration:{capability}:{from}:{to}"),
            prev: last.map_or([0u8; 32], |previous| previous.hash),
            hash: [0u8; 32],
            sig: Vec::new(),
            public_key: self.signer.public_key(),
        };
        entry.hash = sha256(&entry.canonical());
        entry.sig = self.signer.sign(&entry.hash)?;
        self.audit_log.append_global_operation(&entry)
    }

    pub fn verify_global_operations(&self) -> Result<(), AppError> {
        let mut previous = [0u8; 32];
        for (index, entry) in self.audit_log.global_operations()?.iter().enumerate() {
            if entry.case_id != GLOBAL_OPERATION_SCOPE
                || entry.actor != Actor::Analyst
                || entry.seq != index as u64 + 1
                || entry.prev != previous
                || sha256(&entry.canonical()) != entry.hash
                || entry.public_key != self.verifier.trusted_public_key(&entry.actor)?
            {
                return Err(AppError::InvalidChain(entry.seq));
            }
            self.verifier
                .verify(&entry.public_key, &entry.hash, &entry.sig)
                .map_err(|_| AppError::InvalidChain(entry.seq))?;
            previous = entry.hash;
        }
        Ok(())
    }

    fn record_operational_event(&self, id: &CaseId, operation: &str) -> Result<(), AppError> {
        let _case_lock = self.repo.lock_case(id)?;
        self.repo.get_case(id)?;
        self.verify_operations_unlocked(id, &CancellationToken::new())?;
        let last = self.audit_log.last_operation(id)?;
        let mut entry = SignedOperation {
            case_id: id.as_str().into(),
            seq: last.as_ref().map_or(Ok(1), |previous| {
                previous.seq.checked_add(1).ok_or({
                    AppError::Fixed(crate::FixedAppError::PolicyOperationalAuditSequenceExhausted)
                })
            })?,
            at: self.clock.now()?,
            actor: self.signer.actor(),
            operation: operation.into(),
            prev: last.map_or([0u8; 32], |previous| previous.hash),
            hash: [0u8; 32],
            sig: Vec::new(),
            public_key: self.signer.public_key(),
        };
        entry.hash = sha256(&entry.canonical());
        entry.sig = self.signer.sign(&entry.hash)?;
        self.audit_log.append_operation(&entry)
    }
    pub(super) fn verify_operations_unlocked(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let operations = self.audit_log.operations(id)?;
        let mut previous = [0u8; 32];
        for (index, operation) in operations.iter().enumerate() {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            if operation.case_id != id.as_str()
                || operation.seq != index as u64 + 1
                || operation.prev != previous
                || sha256(&operation.canonical()) != operation.hash
                || operation.public_key != self.verifier.trusted_public_key(&operation.actor)?
            {
                return Err(AppError::InvalidChain(operation.seq));
            }
            self.verifier
                .verify(&operation.public_key, &operation.hash, &operation.sig)
                .map_err(|_| AppError::InvalidChain(operation.seq))?;
            previous = operation.hash;
        }
        Ok(())
    }
}
