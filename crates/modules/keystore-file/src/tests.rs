#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{FileKeystore, SecretBackend, SignerBackend};
    use ed25519_dalek::{Signature, VerifyingKey};
    use irmind_domain::Actor;
    use secrecy::{ExposeSecret as _, SecretString};
    use std::fs;

    fn phrase() -> SecretString {
        SecretString::from("a synthetic test passphrase".to_owned())
    }

    #[test]
    fn encrypted_vault_round_trip_and_signature() {
        let home = tempfile::tempdir().unwrap();
        let vault = FileKeystore::open(home.path(), &phrase(), true).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(home.path().join("keystore.enc"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0);
        }
        irmind_testkit::signer_backend_contract(&vault).unwrap();
        irmind_testkit::secret_backend_contract(&vault).unwrap();
        let signer = vault.load(Actor::Analyst).unwrap();
        let public: [u8; 32] = signer.public_key().try_into().unwrap();
        let signature: [u8; 64] = signer.sign(b"synthetic case").unwrap().try_into().unwrap();
        VerifyingKey::from_bytes(&public)
            .unwrap()
            .verify_strict(b"synthetic case", &Signature::from_bytes(&signature))
            .unwrap();
        vault
            .put(
                "SYNTHETIC_API_KEY",
                &SecretString::from("top-secret".to_owned()),
            )
            .unwrap();
        assert!(!format!("{vault:?}").contains("top-secret"));
        drop(signer);
        drop(vault);
        let reopened = FileKeystore::open(home.path(), &phrase(), false).unwrap();
        assert_eq!(
            reopened.public_key_for_actor(&Actor::Analyst).unwrap(),
            public
        );
        assert_eq!(
            reopened.get("SYNTHETIC_API_KEY").unwrap().expose_secret(),
            "top-secret"
        );
        assert!(reopened.get("MISSING_KEY").is_err());
        reopened.delete("SYNTHETIC_API_KEY").unwrap();
        assert!(reopened.get("SYNTHETIC_API_KEY").is_err());
    }

    #[test]
    fn wrong_phrase_and_tampering_fail_closed() {
        let home = tempfile::tempdir().unwrap();
        assert!(
            FileKeystore::open(home.path(), &SecretString::from("short".to_owned()), true).is_err()
        );
        drop(FileKeystore::open(home.path(), &phrase(), true).unwrap());
        let wrong = SecretString::from("wrong passphrase".to_owned());
        assert!(FileKeystore::open(home.path(), &wrong, false).is_err());
        let path = home.path().join("keystore.enc");
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.last_mut().unwrap();
        *last ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(FileKeystore::open(home.path(), &phrase(), false).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn encrypted_store_refuses_a_symbolic_link() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::os::unix::fs::symlink(outside.path(), home.path().join("keystore.enc")).unwrap();
        assert!(FileKeystore::open(home.path(), &phrase(), true).is_err());
    }

    #[test]
    fn unsafe_parameters_and_unknown_version_fail_before_kdf() {
        let home = tempfile::tempdir().unwrap();
        drop(FileKeystore::open(home.path(), &phrase(), true).unwrap());
        let path = home.path().join("keystore.enc");
        let original = fs::read(&path).unwrap();
        let mut weak = original.clone();
        weak[5..9].copy_from_slice(&1024u32.to_be_bytes());
        fs::write(&path, weak).unwrap();
        assert!(
            FileKeystore::open(home.path(), &phrase(), false)
                .unwrap_err()
                .to_string()
                .contains("unsafe")
        );
        let mut future = original;
        future[4] = 255;
        fs::write(&path, future).unwrap();
        assert!(
            FileKeystore::open(home.path(), &phrase(), false)
                .unwrap_err()
                .to_string()
                .contains("version")
        );
    }

    #[test]
    fn changing_phrase_reencrypts_without_changing_identity() {
        let home = tempfile::tempdir().unwrap();
        let vault = FileKeystore::open(home.path(), &phrase(), true).unwrap();
        let original = vault.create(Actor::Analyst).unwrap().public_key();
        let replacement = SecretString::from("new synthetic passphrase".to_owned());
        vault.change_passphrase(&replacement).unwrap();
        drop(vault);
        assert!(FileKeystore::open(home.path(), &phrase(), false).is_err());
        let unlocked = FileKeystore::open(
            home.path(),
            &SecretString::from("new synthetic passphrase".to_owned()),
            false,
        )
        .unwrap();
        assert_eq!(
            unlocked.public_key_for_actor(&Actor::Analyst).unwrap(),
            original
        );
    }

    #[test]
    fn second_session_cannot_unlock_the_same_store_concurrently() {
        let home = tempfile::tempdir().unwrap();
        let first = FileKeystore::open(home.path(), &phrase(), true).unwrap();
        assert!(FileKeystore::open(home.path(), &phrase(), false).is_err());
        drop(first);
        assert!(FileKeystore::open(home.path(), &phrase(), false).is_ok());
    }

    #[test]
    fn signing_identity_moves_in_encrypted_one_use_packet() {
        let source_home = tempfile::tempdir().unwrap();
        let target_home = tempfile::tempdir().unwrap();
        let source = FileKeystore::open(source_home.path(), &phrase(), true).unwrap();
        let target = FileKeystore::open(target_home.path(), &phrase(), true).unwrap();
        let original = source.create(Actor::Analyst).unwrap().public_key();
        let recipient = target.migration_recipient(&Actor::Analyst).unwrap();
        let packet = source.export_wrapped(&Actor::Analyst, &recipient).unwrap();
        assert!(!packet.windows(32).any(|part| part == original.as_slice()));
        target.import_wrapped(Actor::Analyst, &packet).unwrap();
        assert_eq!(target.load(Actor::Analyst).unwrap().public_key(), original);
        let agent = Actor::parse_storage("agent:synthetic").unwrap();
        let agent_public = source.create(agent.clone()).unwrap().public_key();
        let agent_recipient = target.migration_recipient(&agent).unwrap();
        let agent_packet = source.export_wrapped(&agent, &agent_recipient).unwrap();
        target.import_wrapped(agent.clone(), &agent_packet).unwrap();
        assert_eq!(target.load(agent).unwrap().public_key(), agent_public);
        assert_ne!(agent_public, original);
        assert!(target.import_wrapped(Actor::Analyst, &packet).is_err());
        assert!(target.migration_recipient(&Actor::Analyst).is_err());
    }
}
