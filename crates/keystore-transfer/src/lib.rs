#![forbid(unsafe_code)]

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use irmind_app::{AppError, sha256};
use irmind_domain::Actor;
use rand::RngCore as _;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const VERSION: u8 = 1;
const PACKET_LEN: usize = 1 + 32 + 24 + 32 + 16;

fn error() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::AdapterSignature(
        irmind_app::AdapterSignatureError::SigningKeyMigrationFailed,
    ))
}

fn context(actor: &Actor, recipient: &[u8; 32], sender: &[u8; 32]) -> Result<Vec<u8>, AppError> {
    let mut bytes = b"irmind-keystore-transfer-v1\0".to_vec();
    let actor_bytes = actor.as_storage().into_bytes();
    bytes.extend_from_slice(
        &u32::try_from(actor_bytes.len())
            .map_err(|_| error())?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&actor_bytes);
    bytes.extend_from_slice(recipient);
    bytes.extend_from_slice(sender);
    Ok(bytes)
}

pub struct KeyImportSession {
    secret: StaticSecret,
}

impl Default for KeyImportSession {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyImportSession {
    pub fn new() -> Self {
        Self {
            secret: StaticSecret::random_from_rng(rand::rngs::OsRng),
        }
    }

    pub fn recipient(&self) -> [u8; 32] {
        PublicKey::from(&self.secret).to_bytes()
    }

    pub fn unwrap(&self, actor: &Actor, packet: &[u8]) -> Result<Zeroizing<[u8; 32]>, AppError> {
        if packet.len() != PACKET_LEN || packet[0] != VERSION {
            return Err(error());
        }
        let sender_bytes: [u8; 32] = packet[1..33].try_into().map_err(|_| error())?;
        let sender = PublicKey::from(sender_bytes);
        let shared = Zeroizing::new(self.secret.diffie_hellman(&sender).to_bytes());
        if shared.iter().all(|byte| *byte == 0) {
            return Err(error());
        }
        let aad = context(actor, &self.recipient(), &sender_bytes)?;
        let mut material = Zeroizing::new(aad.clone());
        material.extend_from_slice(&*shared);
        let key = Zeroizing::new(sha256(&material));
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let nonce: [u8; 24] = packet[33..57].try_into().map_err(|_| error())?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &packet[57..],
                        aad: &aad,
                    },
                )
                .map_err(|_| error())?,
        );
        Ok(Zeroizing::new(
            <[u8; 32]>::try_from(plain.as_slice()).map_err(|_| error())?,
        ))
    }
}

pub fn wrap_signing_seed(
    actor: &Actor,
    seed: &[u8; 32],
    recipient: &[u8; 32],
) -> Result<Vec<u8>, AppError> {
    let sender_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let sender = PublicKey::from(&sender_secret).to_bytes();
    let shared = Zeroizing::new(
        sender_secret
            .diffie_hellman(&PublicKey::from(*recipient))
            .to_bytes(),
    );
    if shared.iter().all(|byte| *byte == 0) {
        return Err(error());
    }
    let aad = context(actor, recipient, &sender)?;
    let mut material = Zeroizing::new(aad.clone());
    material.extend_from_slice(&*shared);
    let key = Zeroizing::new(sha256(&material));
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let encrypted = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: seed,
                aad: &aad,
            },
        )
        .map_err(|_| error())?;
    let mut packet = Vec::with_capacity(PACKET_LEN);
    packet.push(VERSION);
    packet.extend_from_slice(&sender);
    packet.extend_from_slice(&nonce);
    packet.extend_from_slice(&encrypted);
    Ok(packet)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{KeyImportSession, wrap_signing_seed};
    use irmind_domain::Actor;

    #[test]
    fn wrapped_seed_is_bound_to_actor_and_recipient() {
        let recipient = KeyImportSession::new();
        let seed = [9u8; 32];
        let packet = wrap_signing_seed(&Actor::Analyst, &seed, &recipient.recipient()).unwrap();
        assert_eq!(*recipient.unwrap(&Actor::Analyst, &packet).unwrap(), seed);
        let other = Actor::parse_storage("agent:synthetic").unwrap();
        assert!(recipient.unwrap(&other, &packet).is_err());
        assert!(
            KeyImportSession::new()
                .unwrap(&Actor::Analyst, &packet)
                .is_err()
        );
        let mut tampered = packet;
        tampered[60] ^= 1;
        assert!(recipient.unwrap(&Actor::Analyst, &tampered).is_err());
    }
}
