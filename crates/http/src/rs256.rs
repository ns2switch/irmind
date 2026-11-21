//! RS256 signing for explicit service-account authentication.
use ring::{
    rand::SystemRandom,
    signature::{RSA_PKCS1_SHA256, RsaKeyPair},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Rs256Error;

pub(super) struct Rs256Key(RsaKeyPair);

impl Rs256Key {
    /// Load an RSA private key in PKCS #8 DER form.
    pub(super) fn from_pkcs8(der: &[u8]) -> Result<Self, Rs256Error> {
        RsaKeyPair::from_pkcs8(der)
            .map(Self)
            .map_err(|_| Rs256Error)
    }

    /// Sign the exact caller-provided JWT signing input.
    pub(super) fn sign(&self, input: &[u8]) -> Result<Vec<u8>, Rs256Error> {
        let mut signature = vec![0; self.0.public().modulus_len()];
        self.0
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                input,
                &mut signature,
            )
            .map_err(|_| Rs256Error)?;
        Ok(signature)
    }
}
