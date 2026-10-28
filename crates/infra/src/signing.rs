use crate::*;

pub(crate) fn verify_signature(
    public_key: &[u8],
    message: &[u8],
    sig: &[u8],
) -> Result<(), AppError> {
    let key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| storage_reason("invalid public key size"))?;
    let signature: [u8; 64] = sig
        .try_into()
        .map_err(|_| storage_reason("invalid signature size"))?;
    let key = VerifyingKey::from_bytes(&key).map_err(storage)?;
    key.verify_strict(message, &Signature::from_bytes(&signature))
        .map_err(storage)
}
pub struct LocalSigner {
    pub(crate) key: SigningKey,
    pub(crate) actor: Actor,
}

impl LocalSigner {
    pub fn load_or_create(actor: Actor) -> Result<Self, AppError> {
        let key = load_key(&actor, true)?;
        if matches!(actor, Actor::Agent(_))
            && let Ok(analyst) = load_key(&Actor::Analyst, false)
            && key.verifying_key() == analyst.verifying_key()
        {
            return Err(AppError::Fixed(
                irmind_app::FixedAppError::AdapterSignature(
                    irmind_app::AdapterSignatureError::AgentAndAnalystKeysMustDiffer,
                ),
            ));
        }
        Ok(Self { key, actor })
    }

    pub fn public_key_for_actor(actor: &Actor) -> Result<Vec<u8>, AppError> {
        Ok(load_key(actor, false)?.verifying_key().to_bytes().to_vec())
    }
}

fn load_key(actor: &Actor, create: bool) -> Result<SigningKey, AppError> {
    let name = match actor {
        Actor::Analyst => "local-analyst".to_owned(),
        Actor::Agent(id) => format!("local-agent-{}", id.as_str()),
    };
    let entry = keyring::Entry::new("irmind", &name)
        .map_err(|_| storage_reason("system keyring unavailable"))?;
    match entry.get_password() {
        Ok(value) => {
            let bytes =
                hex::decode(value).map_err(|_| storage_reason("invalid signing key in keyring"))?;
            let key: [u8; 32] = bytes
                .try_into()
                .map_err(|_| storage_reason("keyring key must be 32 bytes"))?;
            Ok(SigningKey::from_bytes(&key))
        }
        Err(keyring::Error::NoEntry) if create => {
            let key = SigningKey::generate(&mut rand::rngs::OsRng);
            entry
                .set_password(&hex::encode(key.to_bytes()))
                .map_err(|_| storage_reason("system keyring unavailable"))?;
            Ok(key)
        }
        Err(_) => Err(storage_reason("system keyring unavailable")),
    }
}

impl Signer for LocalSigner {
    fn actor(&self) -> Actor {
        self.actor.clone()
    }
    fn public_key(&self) -> Vec<u8> {
        self.key.verifying_key().to_bytes().to_vec()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AppError> {
        Ok(self.key.sign(message).to_bytes().to_vec())
    }
}

#[derive(Clone)]
pub struct LocalVerifier {
    pub(crate) trusted: std::collections::BTreeMap<String, Vec<u8>>,
}

impl LocalVerifier {
    pub fn from_signer(signer: &dyn Signer) -> Self {
        Self {
            trusted: std::collections::BTreeMap::from([(
                signer.actor().as_storage(),
                signer.public_key(),
            )]),
        }
    }

    pub fn with_trusted_key(mut self, actor: &Actor, key: &[u8]) -> Result<Self, AppError> {
        if key.len() != 32 {
            return Err(AppError::Fixed(
                irmind_app::FixedAppError::AdapterSignature(
                    irmind_app::AdapterSignatureError::InvalidTrustedPublicKey,
                ),
            ));
        }
        if self
            .trusted
            .iter()
            .any(|(name, existing)| name != &actor.as_storage() && existing == key)
        {
            return Err(AppError::Fixed(
                irmind_app::FixedAppError::AdapterSignature(
                    irmind_app::AdapterSignatureError::ActorsShareAPublicKey,
                ),
            ));
        }
        if self
            .trusted
            .insert(actor.as_storage(), key.to_vec())
            .is_some_and(|existing| existing != key)
        {
            return Err(AppError::Fixed(
                irmind_app::FixedAppError::AdapterSignature(
                    irmind_app::AdapterSignatureError::TrustedActorKeyChanged,
                ),
            ));
        }
        Ok(self)
    }
}

impl Verifier for LocalVerifier {
    fn trusted_public_key(&self, actor: &Actor) -> Result<Vec<u8>, AppError> {
        self.trusted.get(&actor.as_storage()).cloned().ok_or({
            AppError::Fixed(irmind_app::FixedAppError::AdapterSignature(
                irmind_app::AdapterSignatureError::ActorPublicKeyIsNotTrusted,
            ))
        })
    }

    fn verify(&self, public_key: &[u8], message: &[u8], sig: &[u8]) -> Result<(), AppError> {
        verify_signature(public_key, message, sig)
    }
}

pub struct LocalAnalystVerifier(pub(crate) VerifyingKey);

impl AnalystApprovalVerifier for LocalAnalystVerifier {
    fn verify_analyst(&self, message: &[u8], signature: &[u8]) -> bool {
        let Ok(bytes): Result<[u8; 64], _> = signature.try_into() else {
            return false;
        };
        self.0
            .verify_strict(message, &Signature::from_bytes(&bytes))
            .is_ok()
    }
}
