use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AdapterSignatureError {
    #[error("signature: OS signing key changed during session")]
    OSSigningKeyChangedDuringSession,
    #[error("signature: actor public key is not trusted")]
    ActorPublicKeyIsNotTrusted,
    #[error("signature: actors share a public key")]
    ActorsShareAPublicKey,
    #[error("signature: agent and analyst keys must differ")]
    AgentAndAnalystKeysMustDiffer,
    #[error("signature: analyst key fingerprint mismatch")]
    AnalystKeyFingerprintMismatch,
    #[error("signature: export key does not match expected fingerprint")]
    ExportKeyDoesNotMatchExpectedFingerprint,
    #[error("signature: invalid trusted public key")]
    InvalidTrustedPublicKey,
    #[error("signature: signing key changed during creation")]
    SigningKeyChangedDuringCreation,
    #[error("signature: signing key not found")]
    SigningKeyNotFound,
    #[error("signature: signing-key migration failed")]
    SigningKeyMigrationFailed,
    #[error("signature: trusted actor key changed")]
    TrustedActorKeyChanged,
}
