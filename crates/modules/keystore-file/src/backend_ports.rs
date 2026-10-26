impl SignerBackend for FileKeystore {
    fn manifest(&self) -> &'static KeystoreManifest {
        &MANIFEST
    }

    fn load(&self, actor: Actor) -> Result<Arc<dyn Signer>, AppError> {
        let public_key = self.with_state(|state| {
            let bytes = state
                .records
                .get(&record_name(&actor))
                .ok_or(AppError::Fixed(
                    irmind_app::FixedAppError::AdapterSignature(
                        irmind_app::AdapterSignatureError::SigningKeyNotFound,
                    ),
                ))?;
            let seed =
                Zeroizing::new(<[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| failure())?);
            let key = SigningKey::from_bytes(&seed);
            if matches!(actor, Actor::Agent(_))
                && let Some(analyst) = state.records.get(&record_name(&Actor::Analyst))
            {
                let analyst_seed = Zeroizing::new(
                    <[u8; 32]>::try_from(analyst.as_slice()).map_err(|_| failure())?,
                );
                if key.verifying_key() == SigningKey::from_bytes(&analyst_seed).verifying_key() {
                    return Err(AppError::Fixed(
                        irmind_app::FixedAppError::AdapterSignature(
                            irmind_app::AdapterSignatureError::AgentAndAnalystKeysMustDiffer,
                        ),
                    ));
                }
            }
            Ok(key.verifying_key().to_bytes().to_vec())
        })?;
        Ok(Arc::new(FileSigner {
            vault: self.vault.clone(),
            actor,
            public_key,
        }))
    }

    fn create(&self, actor: Actor) -> Result<Arc<dyn Signer>, AppError> {
        self.with_state(|state| {
            let name = record_name(&actor);
            if state.records.contains_key(&name) {
                return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                    irmind_app::AdapterPolicyError::SigningKeyAlreadyExists,
                )));
            }
            let key = SigningKey::generate(&mut rand::rngs::OsRng);
            state
                .records
                .insert(name.clone(), Zeroizing::new(key.to_bytes().to_vec()));
            if let Err(error) = persist(&self.vault, state) {
                if !self.vault.poisoned.load(Ordering::SeqCst) {
                    state.records.remove(&name);
                }
                return Err(error);
            }
            Ok(())
        })?;
        self.load(actor)
    }

    fn public_key_for_actor(&self, actor: &Actor) -> Result<Vec<u8>, AppError> {
        self.load(actor.clone()).map(|signer| signer.public_key())
    }

    fn migration_recipient(&self, actor: &Actor) -> Result<[u8; 32], AppError> {
        self.with_state(|state| {
            if state.records.contains_key(&record_name(actor)) {
                return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                    irmind_app::AdapterPolicyError::DestinationSigningKeyAlreadyExists,
                )));
            }
            Ok(())
        })?;
        let session = KeyImportSession::new();
        let recipient = session.recipient();
        self.vault
            .imports
            .lock()
            .map_err(|_| failure())?
            .insert(actor.as_storage(), session);
        Ok(recipient)
    }

    fn export_wrapped(&self, actor: &Actor, recipient: &[u8; 32]) -> Result<Vec<u8>, AppError> {
        self.with_state(|state| {
            let bytes = state.records.get(&record_name(actor)).ok_or_else(failure)?;
            let seed =
                Zeroizing::new(<[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| failure())?);
            wrap_signing_seed(actor, &seed, recipient)
        })
    }

    fn import_wrapped(&self, actor: Actor, packet: &[u8]) -> Result<(), AppError> {
        let session = self
            .vault
            .imports
            .lock()
            .map_err(|_| failure())?
            .remove(&actor.as_storage())
            .ok_or_else(failure)?;
        let seed = session.unwrap(&actor, packet)?;
        self.with_state(|state| {
            let name = record_name(&actor);
            if state.records.contains_key(&name) {
                return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                    irmind_app::AdapterPolicyError::DestinationSigningKeyAlreadyExists,
                )));
            }
            if matches!(actor, Actor::Agent(_))
                && let Some(analyst) = state.records.get(&record_name(&Actor::Analyst))
            {
                let analyst_seed = Zeroizing::new(
                    <[u8; 32]>::try_from(analyst.as_slice()).map_err(|_| failure())?,
                );
                if SigningKey::from_bytes(&seed).verifying_key()
                    == SigningKey::from_bytes(&analyst_seed).verifying_key()
                {
                    return Err(AppError::Fixed(
                        irmind_app::FixedAppError::AdapterSignature(
                            irmind_app::AdapterSignatureError::AgentAndAnalystKeysMustDiffer,
                        ),
                    ));
                }
            }
            state
                .records
                .insert(name.clone(), Zeroizing::new(seed.to_vec()));
            if let Err(error) = persist(&self.vault, state) {
                if !self.vault.poisoned.load(Ordering::SeqCst) {
                    state.records.remove(&name);
                }
                return Err(error);
            }
            Ok(())
        })
    }
}

impl Signer for FileSigner {
    fn actor(&self) -> Actor {
        self.actor.clone()
    }
    fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AppError> {
        let state = self.vault.state.lock().map_err(|_| failure())?;
        if self.vault.poisoned.load(Ordering::SeqCst) {
            return Err(failure());
        }
        let bytes = state
            .records
            .get(&record_name(&self.actor))
            .ok_or_else(failure)?;
        let seed = Zeroizing::new(<[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| failure())?);
        Ok(SigningKey::from_bytes(&seed)
            .sign(message)
            .to_bytes()
            .to_vec())
    }
}

impl SecretBackend for FileKeystore {
    fn manifest(&self) -> &'static KeystoreManifest {
        &MANIFEST
    }
    fn get(&self, name: &str) -> Result<SecretString, AppError> {
        let name = secret_name(name)?;
        self.with_state(|state| {
            let bytes = state.records.get(&name).ok_or(AppError::SecretMissing)?;
            let scratch = Zeroizing::new(bytes.to_vec());
            let value = std::str::from_utf8(&scratch)
                .map_err(|_| failure())?
                .to_owned();
            Ok(SecretString::from(value))
        })
    }
    fn put(&self, name: &str, secret: &SecretString) -> Result<(), AppError> {
        let name = secret_name(name)?;
        if secret.expose_secret().is_empty() || secret.expose_secret().len() > 4096 {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidModuleSecretLength,
            )));
        }
        self.with_state(|state| {
            let old = state.records.insert(
                name.clone(),
                Zeroizing::new(secret.expose_secret().as_bytes().to_vec()),
            );
            if let Err(error) = persist(&self.vault, state) {
                if !self.vault.poisoned.load(Ordering::SeqCst) {
                    state.records.remove(&name);
                    if let Some(old) = old {
                        state.records.insert(name, old);
                    }
                }
                return Err(error);
            }
            Ok(())
        })
    }
    fn delete(&self, name: &str) -> Result<(), AppError> {
        let name = secret_name(name)?;
        self.with_state(|state| {
            let old = state.records.remove(&name).ok_or(AppError::SecretMissing)?;
            if let Err(error) = persist(&self.vault, state) {
                if !self.vault.poisoned.load(Ordering::SeqCst) {
                    state.records.insert(name, old);
                }
                return Err(error);
            }
            Ok(())
        })
    }
}
