pub fn signer_backend_contract(backend: &dyn SignerBackend) -> Result<(), String> {
    if !backend
        .manifest()
        .capabilities
        .contains(&KeystoreCapability::Signer)
    {
        return Err("signer capability missing from manifest".into());
    }
    let signer = backend
        .create(Actor::Analyst)
        .map_err(|error| error.to_string())?;
    let public = signer.public_key();
    if backend
        .public_key_for_actor(&Actor::Analyst)
        .map_err(|error| error.to_string())?
        != public
    {
        return Err("backend public key differs from signer".into());
    }
    let key: [u8; 32] = public.try_into().map_err(|_| "invalid public key length")?;
    let signature: [u8; 64] = signer
        .sign(b"IRMind synthetic contract")
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "invalid signature length")?;
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .map_err(|_| "invalid public key")?
        .verify_strict(
            b"IRMind synthetic contract",
            &ed25519_dalek::Signature::from_bytes(&signature),
        )
        .map_err(|_| "signature did not verify")?;
    if backend.create(Actor::Analyst).is_ok() {
        return Err("backend replaced an existing analyst key".into());
    }
    let agent = Actor::parse_storage("agent:contract").map_err(|_| "invalid test actor")?;
    let agent_signer = backend
        .create(agent.clone())
        .map_err(|error| error.to_string())?;
    if agent_signer.public_key().as_slice() == key.as_slice() || agent_signer.actor() != agent {
        return Err("agent and analyst signing identities were not separate".into());
    }
    let agent_key: [u8; 32] = agent_signer
        .public_key()
        .try_into()
        .map_err(|_| "invalid agent public key")?;
    let agent_sig: [u8; 64] = agent_signer
        .sign(b"IRMind synthetic agent contract")
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "invalid agent signature")?;
    ed25519_dalek::VerifyingKey::from_bytes(&agent_key)
        .map_err(|_| "invalid agent public key")?
        .verify_strict(
            b"IRMind synthetic agent contract",
            &ed25519_dalek::Signature::from_bytes(&agent_sig),
        )
        .map_err(|_| "agent signature did not verify")?;
    Ok(())
}

pub fn secret_backend_contract(backend: &dyn SecretBackend) -> Result<(), String> {
    use secrecy::{ExposeSecret as _, SecretString};
    if !backend
        .manifest()
        .capabilities
        .contains(&KeystoreCapability::Secrets)
    {
        return Err("secrets capability missing from manifest".into());
    }
    let name = "SYNTHETIC_CONTRACT_SECRET";
    let missing = backend
        .get(name)
        .err()
        .ok_or("missing secret returned a value")?;
    if !matches!(missing, AppError::SecretMissing) {
        return Err("missing secret did not return SecretMissing".into());
    }
    if missing.to_string().contains("synthetic-value") {
        return Err("error exposed a secret".into());
    }
    let value = SecretString::from("synthetic-value".to_owned());
    backend
        .put(name, &value)
        .map_err(|error| error.to_string())?;
    let loaded = backend.get(name).map_err(|error| error.to_string())?;
    if loaded.expose_secret() != "synthetic-value"
        || format!("{loaded:?}").contains("synthetic-value")
    {
        return Err("secret value or Debug contract failed".into());
    }
    backend
        .put(name, &SecretString::from("replacement".to_owned()))
        .map_err(|error| error.to_string())?;
    if backend
        .get(name)
        .map_err(|error| error.to_string())?
        .expose_secret()
        != "replacement"
    {
        return Err("secret replacement failed".into());
    }
    backend.delete(name).map_err(|error| error.to_string())?;
    if backend.get(name).is_ok() {
        return Err("deleted secret remained available".into());
    }
    Ok(())
}
