use super::*;
fn empty() -> ClusterPrompt {
    ClusterPrompt::new(
        "synthetic-audit.ndjson".into(),
        &ParserClusterRequirement::try_new(true, vec![]).unwrap(),
    )
}
#[test]
fn keyboard_and_paste_never_apply_a_cluster_without_confirmation() {
    let mut prompt = empty();
    assert!(prompt.value.is_empty());
    prompt.paste("kubernetes:urn:k8s:team-a\r\n");
    assert!(matches!(
        prompt.update(KeyCode::Enter, KeyModifiers::NONE),
        ClusterPromptAction::Keep
    ));
    match prompt.update(KeyCode::Enter, KeyModifiers::NONE) {
        ClusterPromptAction::Confirm { context, all_files } => {
            assert!(!all_files);
            assert_eq!(
                context.bindings()[0].identity().qualified(),
                "kubernetes:urn:k8s:team-a"
            );
            assert_eq!(context.bindings()[0].basis(), ClusterContextBasis::Analyst);
        }
        _ => unreachable!(),
    }
}
#[test]
fn malformed_identity_stays_in_form_and_batch_reuse_is_explicit() {
    let mut prompt = empty();
    prompt.paste("../not-an-identity");
    prompt.focus = 3;
    assert!(matches!(
        prompt.update(KeyCode::Enter, KeyModifiers::NONE),
        ClusterPromptAction::Keep
    ));
    assert!(prompt.error.is_some());
    prompt.focus = 0;
    prompt.update(KeyCode::Char('u'), KeyModifiers::CONTROL);
    assert!(prompt.value.is_empty());
    prompt.paste("kubernetes:urn:k8s:team-a");
    prompt.update(KeyCode::Tab, KeyModifiers::NONE);
    prompt.update(KeyCode::Enter, KeyModifiers::NONE);
    assert!(prompt.all_files);
    assert!(matches!(
        prompt.update(KeyCode::Esc, KeyModifiers::NONE),
        ClusterPromptAction::Cancel
    ));
}
#[test]
fn wrapper_claims_remain_suggestions_until_explicitly_confirmed() {
    let identity = ClusterIdentity::try_new(
        irmind_app::ClusterProvider::Gke,
        "projects/synthetic/locations/us-central1/clusters/lab",
    )
    .unwrap();
    let mut prompt = ClusterPrompt::new(
        "synthetic-gke.json".into(),
        &ParserClusterRequirement::try_new(true, vec![identity.clone()]).unwrap(),
    );
    assert!(prompt.value.is_empty());
    prompt.update(KeyCode::Tab, KeyModifiers::NONE);
    prompt.update(KeyCode::Tab, KeyModifiers::NONE);
    match prompt.update(KeyCode::Enter, KeyModifiers::NONE) {
        ClusterPromptAction::Confirm { context, .. } => {
            assert_eq!(
                context.bindings()[0].basis(),
                ClusterContextBasis::ConfirmedSource
            );
            assert_eq!(context.resolve(Some(&identity)).unwrap(), &identity);
            assert!(context.resolve(None).is_err());
        }
        _ => unreachable!(),
    }
}
struct Guard;
impl ContentGuard for Guard {
    fn fingerprint(&self) -> String {
        "synthetic-cluster-form".into()
    }
    fn self_test(&self) -> Result<(), AppError> {
        Ok(())
    }
    fn screen(&self, value: &str) -> Result<irmind_app::Screened, AppError> {
        Ok(irmind_app::Screened {
            text: crate::case::escape_display(value),
            detections: vec![],
        })
    }
}
#[test]
fn cluster_confirmation_is_readable_at_80_columns_and_source_text_is_escaped() {
    use ratatui::{
        Terminal,
        backend::TestBackend,
        widgets::{Paragraph, Wrap},
    };
    let mut prompt = empty();
    prompt.source = "synthetic\u{1b}[31m-audit.ndjson".into();
    let text = prompt.screened_text(&Guard).unwrap();
    assert!(!text.contains('\u{1b}'));
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| {
            frame.render_widget(
                Paragraph::new(text).wrap(Wrap { trim: false }),
                frame.area(),
            );
        })
        .unwrap();
    let buffer = terminal.backend().buffer();
    let screen = (0..24)
        .map(|y| {
            (0..80)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
                .trim_end()
                .to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n");
    insta::assert_snapshot!("kubernetes_cluster_confirmation", screen);
}
