use super::{Scenario, model::Episode};
pub(super) fn record(
    scenario: &Scenario,
    models: &[Episode],
    store: &irmind_infra::LocalStore,
    id: &irmind_app::CaseId,
    suffix: &str,
) {
    let requests = models
        .iter()
        .map(|m| m.requests.lock().unwrap())
        .collect::<Vec<_>>();
    let turns = requests.iter().map(|r| r.as_slice()).collect::<Vec<_>>();
    super::super::measurement::record(
        scenario.name,
        &turns,
        models.iter().map(|m| m.final_text().len()).sum(),
        store,
        id,
        suffix,
    );
}
