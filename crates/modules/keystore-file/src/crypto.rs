use crate::*;

pub(super) fn derive(
    passphrase: &SecretString,
    salt: &[u8; 16],
    memory: u32,
    passes: u32,
    lanes: u32,
) -> Result<Zeroizing<[u8; 32]>, AppError> {
    if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&memory)
        || !(MIN_PASSES..=MAX_PASSES).contains(&passes)
        || !(1..=4).contains(&lanes)
        || passphrase.expose_secret().len() < MIN_PASSPHRASE_BYTES
    {
        return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
            irmind_app::AdapterStorageError::EncryptedKeystoreParametersAreUnsafe,
        )));
    }
    let params = Params::new(memory, passes, lanes, Some(32)).map_err(|_| failure())?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.expose_secret().as_bytes(), salt, &mut *key)
        .map_err(|_| failure())?;
    Ok(key)
}

fn read_u32(bytes: &[u8]) -> Result<u32, AppError> {
    Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| failure())?))
}

fn read_records(bytes: &[u8]) -> Result<BTreeMap<String, Zeroizing<Vec<u8>>>, AppError> {
    if bytes.len() < 4 || bytes.len() > MAX_FILE_BYTES {
        return Err(failure());
    }
    let mut offset = 4usize;
    let count = read_u32(&bytes[..4])? as usize;
    if count > 1024 {
        return Err(failure());
    }
    let mut records = BTreeMap::new();
    for _ in 0..count {
        let length = usize::from(*bytes.get(offset).ok_or_else(failure)?);
        offset += 1;
        if length == 0 || length > 100 || offset + length + 4 > bytes.len() {
            return Err(failure());
        }
        let name = std::str::from_utf8(&bytes[offset..offset + length])
            .map_err(|_| failure())?
            .to_owned();
        offset += length;
        let data_len = read_u32(&bytes[offset..offset + 4])? as usize;
        offset += 4;
        if data_len == 0 || data_len > 4096 || offset + data_len > bytes.len() {
            return Err(failure());
        }
        let data = Zeroizing::new(bytes[offset..offset + data_len].to_vec());
        offset += data_len;
        if records.insert(name, data).is_some() {
            return Err(failure());
        }
    }
    if offset != bytes.len() {
        return Err(failure());
    }
    Ok(records)
}

fn encode_records(
    records: &BTreeMap<String, Zeroizing<Vec<u8>>>,
) -> Result<Zeroizing<Vec<u8>>, AppError> {
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(
        &u32::try_from(records.len())
            .map_err(|_| failure())?
            .to_be_bytes(),
    );
    for (name, data) in records {
        let name_len = u8::try_from(name.len()).map_err(|_| failure())?;
        let data_len = u32::try_from(data.len()).map_err(|_| failure())?;
        out.push(name_len);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&data_len.to_be_bytes());
        out.extend_from_slice(data);
    }
    if out.len() > MAX_FILE_BYTES {
        return Err(failure());
    }
    Ok(out)
}

fn encrypt(state: &VaultState) -> Result<Zeroizing<Vec<u8>>, AppError> {
    let plain = encode_records(&state.records)?;
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new((&*state.key).into());
    let ciphertext_len = plain.len().checked_add(16).ok_or_else(failure)?;
    let mut output = Zeroizing::new(Vec::with_capacity(HEADER_LEN + ciphertext_len));
    output.extend_from_slice(MAGIC);
    output.push(VERSION);
    output.extend_from_slice(&MIN_MEMORY_KIB.to_be_bytes());
    output.extend_from_slice(&MIN_PASSES.to_be_bytes());
    output.extend_from_slice(&1u32.to_be_bytes());
    output.extend_from_slice(&state.salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(
        &u32::try_from(ciphertext_len)
            .map_err(|_| failure())?
            .to_be_bytes(),
    );
    let encrypted = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plain,
                aad: &output,
            },
        )
        .map_err(|_| failure())?;
    output.extend_from_slice(&encrypted);
    Ok(output)
}

pub(super) fn decrypt(bytes: &[u8], passphrase: &SecretString) -> Result<VaultState, AppError> {
    if bytes.len() < HEADER_LEN + 16 || bytes.len() > MAX_FILE_BYTES || &bytes[..4] != MAGIC {
        return Err(failure());
    }
    if bytes[4] != VERSION {
        return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
            irmind_app::AdapterStorageError::UnknownEncryptedKeystoreVersion,
        )));
    }
    let memory = read_u32(&bytes[5..9])?;
    let passes = read_u32(&bytes[9..13])?;
    let lanes = read_u32(&bytes[13..17])?;
    let salt: [u8; 16] = bytes[17..33].try_into().map_err(|_| failure())?;
    let nonce: [u8; 24] = bytes[33..57].try_into().map_err(|_| failure())?;
    let length = read_u32(&bytes[57..61])? as usize;
    if length < 16 || length != bytes.len() - HEADER_LEN {
        return Err(failure());
    }
    let key = derive(passphrase, &salt, memory, passes, lanes)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &bytes[HEADER_LEN..],
                    aad: &bytes[..HEADER_LEN],
                },
            )
            .map_err(|_| {
                AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                    irmind_app::AdapterStorageError::CannotUnlockEncryptedKeystore,
                ))
            })?,
    );
    Ok(VaultState {
        key,
        salt,
        records: read_records(&plain)?,
    })
}

pub(super) fn persist(vault: &Vault, state: &VaultState) -> Result<(), AppError> {
    let bytes = encrypt(state)?;
    let mut suffix = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let path = vault
        .path
        .with_extension(format!("tmp-{:016x}", u64::from_be_bytes(suffix)));
    let mut replace_started = false;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| failure())?;
        irmind_fs::private_file(&path).map_err(|_| failure())?;
        file.write_all(&bytes).map_err(|_| failure())?;
        file.sync_all().map_err(|_| failure())?;
        replace_started = true;
        irmind_fs::durable_replace(&path, &vault.path).map_err(|_| failure())?;
        irmind_fs::sync_directory(vault.path.parent().ok_or_else(failure)?)
            .map_err(|_| failure())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(path);
        if replace_started {
            // A failed replace or directory sync leaves the commit state uncertain.
            // Block every subsequent operation until the vault is reopened.
            vault.poisoned.store(true, Ordering::SeqCst);
        }
    }
    result
}
