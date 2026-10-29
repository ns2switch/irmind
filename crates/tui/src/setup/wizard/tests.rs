use super::*;
use ratatui::backend::TestBackend;

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}
fn enter(wizard: &mut KeystoreWizard) -> WizardAction {
    wizard.key(key(KeyCode::Enter))
}
fn type_text(wizard: &mut KeystoreWizard, text: &str) {
    for ch in text.chars() {
        wizard.key(key(KeyCode::Char(ch)));
    }
}

fn screen(terminal: &Terminal<TestBackend>) -> String {
    (0..24)
        .map(|y| {
            (0..80)
                .map(|x| terminal.backend().buffer()[(x, y)].symbol())
                .collect::<String>()
                .trim_end_matches(' ')
                .to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn welcome_and_backend_have_versioned_snapshots() {
    let mut wizard = KeystoreWizard::new(None, false, true, false);
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    render(&mut terminal, &wizard).unwrap();
    insta::assert_snapshot!("keystore_welcome", screen(&terminal));
    enter(&mut wizard);
    render(&mut terminal, &wizard).unwrap();
    insta::assert_snapshot!("keystore_backend", screen(&terminal));
}

#[test]
fn file_creation_rejects_short_and_mismatched_passphrases() {
    let mut wizard = KeystoreWizard::new(None, false, true, false);
    assert_eq!(enter(&mut wizard), WizardAction::None);
    assert_eq!(enter(&mut wizard), WizardAction::None);
    assert_eq!(enter(&mut wizard), WizardAction::None);
    assert_eq!(wizard.step, Step::Passphrase);
    type_text(&mut wizard, "short");
    enter(&mut wizard);
    assert!(wizard.error.as_deref().unwrap().contains("12"));
    wizard.password = SecretString::from(String::new());
    type_text(&mut wizard, "long synthetic phrase");
    enter(&mut wizard);
    assert_eq!(wizard.step, Step::Confirm);
    type_text(&mut wizard, "different synthetic phrase");
    enter(&mut wizard);
    assert!(wizard.error.as_deref().unwrap().contains("do not match"));
    type_text(&mut wizard, "long synthetic phrase");
    assert_eq!(enter(&mut wizard), WizardAction::Attempt);
    wizard.attempted(Ok("synthetic-fingerprint".into()));
    assert_eq!(wizard.step, Step::Complete);
    assert_eq!(enter(&mut wizard), WizardAction::Done);
}

#[test]
fn unavailable_os_backend_can_switch_to_file_and_retry_unlock() {
    let mut wizard = KeystoreWizard::new(
        Some(KeystoreChoice {
            signer: "os",
            secrets: "os",
        }),
        false,
        true,
        true,
    );
    wizard.key(key(KeyCode::Esc));
    assert_eq!(wizard.step, Step::Backend);
    assert_eq!(wizard.backend_cursor, "file");
    wizard.key(key(KeyCode::Up));
    assert_eq!(wizard.backend_cursor, "file");
    enter(&mut wizard);
    enter(&mut wizard);
    assert_eq!(wizard.step, Step::Unlock);
    assert_eq!(
        (wizard.choice.signer, wizard.choice.secrets),
        ("file", "file")
    );
    assert!(wizard.error.is_none());
    type_text(&mut wizard, "incorrect phrase");
    assert_eq!(enter(&mut wizard), WizardAction::Attempt);
    wizard.attempted(Err("Incorrect passphrase or damaged vault".into()));
    assert_eq!(wizard.step, Step::Unlock);
    wizard.password = SecretString::from(String::new());
    type_text(&mut wizard, "correct synthetic phrase");
    assert_eq!(enter(&mut wizard), WizardAction::Attempt);
    wizard.attempted(Ok("synthetic-fingerprint".into()));
    assert_eq!(wizard.step, Step::Complete);
}

#[test]
fn password_never_reaches_test_backend_or_debug() {
    let mut wizard = KeystoreWizard::new(None, false, true, false);
    enter(&mut wizard);
    enter(&mut wizard);
    enter(&mut wizard);
    type_text(&mut wizard, "synthetic super secret");
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    render(&mut terminal, &wizard).unwrap();
    let buffer_text = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(ratatui::buffer::Cell::symbol)
        .collect::<String>();
    assert!(!buffer_text.contains("synthetic super secret"));
    assert!(buffer_text.contains("Strength"));
    insta::assert_snapshot!("keystore_passphrase", screen(&terminal));
}

#[test]
fn control_c_requires_confirmation_and_escape_goes_back() {
    let mut wizard = KeystoreWizard::new(None, false, true, false);
    enter(&mut wizard);
    assert_eq!(wizard.step, Step::Backend);
    wizard.key(key(KeyCode::Esc));
    assert_eq!(wizard.step, Step::Welcome);
    let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
    assert_eq!(wizard.key(ctrl_c), WizardAction::None);
    assert_eq!(wizard.key(key(KeyCode::Char('n'))), WizardAction::None);
    assert_eq!(wizard.key(ctrl_c), WizardAction::None);
    assert_eq!(wizard.key(key(KeyCode::Char('y'))), WizardAction::Exit);
}

#[test]
fn wizard_error_snapshot_shows_recovery_choices() {
    let mut wizard = KeystoreWizard::new(
        Some(KeystoreChoice {
            signer: "file",
            secrets: "file",
        }),
        false,
        true,
        true,
    );
    wizard.error =
        Some("Incorrect passphrase or damaged vault. Retry or choose another backend.".into());
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    render(&mut terminal, &wizard).unwrap();
    insta::assert_snapshot!("keystore_unlock_error", screen(&terminal));
}

#[test]
fn startup_error_escapes_terminal_and_bidi_controls() {
    let mut wizard = KeystoreWizard::new(None, false, true, false);
    wizard.error = Some("unwritable \u{1b}[31m/path\u{202e}".into());
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    render(&mut terminal, &wizard).unwrap();
    let visible = screen(&terminal);
    assert!(!visible.contains('\u{1b}'));
    assert!(!visible.contains('\u{202e}'));
    assert!(visible.contains("/path"));
}

#[test]
fn unwritable_directory_error_stays_in_wizard_with_retry() {
    let mut wizard = KeystoreWizard::new(None, false, true, false);
    enter(&mut wizard);
    enter(&mut wizard);
    enter(&mut wizard);
    type_text(&mut wizard, "synthetic long passphrase");
    enter(&mut wizard);
    type_text(&mut wizard, "synthetic long passphrase");
    assert_eq!(enter(&mut wizard), WizardAction::Attempt);
    wizard.attempted(Err(
        "Cannot write /synthetic/private: permission denied".into()
    ));
    assert_eq!(wizard.step, Step::Passphrase);
    assert!(
        wizard
            .error
            .as_deref()
            .unwrap()
            .contains("permission denied")
    );
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    render(&mut terminal, &wizard).unwrap();
    let screen = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(ratatui::buffer::Cell::symbol)
        .collect::<String>();
    assert!(screen.contains("Retry"));
    assert!(!screen.contains("synthetic long passphrase"));
}

#[test]
fn backend_list_selects_each_capability_with_arrows_and_enter() {
    let mut wizard = KeystoreWizard::new(None, true, true, false);
    enter(&mut wizard);
    assert_eq!(wizard.backend_cursor, "os");
    wizard.key(key(KeyCode::Down));
    assert_eq!(wizard.backend_cursor, "file");
    enter(&mut wizard);
    assert_eq!(wizard.backend_field, BackendField::Secrets);
    assert_eq!(wizard.choice.signer, "file");
    wizard.key(key(KeyCode::Down));
    enter(&mut wizard);
    assert_eq!(wizard.choice.secrets, "file");
    assert_eq!(wizard.step, Step::Passphrase);
}
