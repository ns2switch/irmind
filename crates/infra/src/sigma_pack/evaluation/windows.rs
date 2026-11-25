use super::*;
use crate::sigma_pack::field_table::ReviewedSigmaFieldTable;
use irmind_app::v10_proofs::SigmaFieldTableV1;
use irmind_domain::{
    BoundedObservations, EventContextV1, EventHeaderV1, EventOrigin, EventText, EvidenceHash,
};

const SECURITY: &str =
    include_str!("../../../../testkit/fixtures/mapping-evtx/protocol/security.jsonl");
const SYSMON: &str =
    include_str!("../../../../testkit/fixtures/mapping-evtx/protocol/sysmon.jsonl");
const POWERSHELL: &str =
    include_str!("../../../../testkit/fixtures/mapping-evtx/protocol/powershell.jsonl");

fn windows_table() -> ReviewedSigmaFieldTable {
    ReviewedSigmaFieldTable::parse(&SigmaFieldTableV1 {
        id: "windows-contract-fixtures".into(),
        version: "v1".into(),
        toml: include_str!("../windows-v1.toml").into(),
    })
    .unwrap()
}

fn raw_rows(fixture: &str) -> impl Iterator<Item = Value> + '_ {
    fixture.lines().filter_map(|line| {
        let value: Value = serde_json::from_str(line).unwrap();
        value.get("event").cloned()
    })
}

fn common(variant: &SigmaSourceVariant, raw: &Value) -> CommonEventV1 {
    let mut context = EventContextV1::default();
    for (field, path) in [
        (CommonField::HostName, &raw["Event"]["System"]["Computer"]),
        (
            CommonField::ProcessExecutable,
            &raw["Event"]["EventData"]["Image"],
        ),
        (
            CommonField::ProcessParentExecutable,
            &raw["Event"]["EventData"]["ParentImage"],
        ),
        (
            CommonField::ProcessCommandLine,
            &raw["Event"]["EventData"]["CommandLine"],
        ),
    ] {
        if let Some(text) = path.as_str() {
            let value = CommonValue::Text(EventText::new(text).unwrap());
            context.try_insert(field, value).unwrap();
        }
    }
    CommonEventV1::try_new(
        EventOrigin::try_new(
            EvidenceHash::from_bytes([42; 32]),
            0,
            Some(4608),
            &variant.parser_id,
            &variant.parser_version,
        )
        .unwrap(),
        None,
        EventHeaderV1::default(),
        context,
        BoundedObservations::default(),
    )
    .unwrap()
}

fn match_count(variant: &SigmaSourceVariant, raw: &Value, rule: &str) -> usize {
    let rule = rule.as_bytes();
    let programs = SigmaVariantPrograms::compile(
        variant,
        [(
            SigmaRuleKeyV1 {
                id: "synthetic-evtx".into(),
                sha256: irmind_app::sha256(rule),
            },
            rule,
        )],
    )
    .unwrap();
    assert_eq!(programs.eligible(), 1);
    let event = common(variant, raw);
    let mut matches = 0;
    assert!(
        programs
            .start(100_000)
            .row(
                &event,
                Some(&raw.to_string()),
                &CancellationToken::new(),
                |_| {
                    matches += 1;
                    Ok(())
                }
            )
            .unwrap()
    );
    matches
}

#[test]
fn sigma_evtx_channel_and_provider_scoped_event_fields_match_exact_rows() {
    let table = windows_table();
    for (fixture, service, id, selection) in [
        (
            SECURITY,
            "security",
            "4625",
            "{EventID: 4625, TargetUserName: alice}",
        ),
        (
            SYSMON,
            "sysmon",
            "1",
            "{EventID: 1, 'Image|endswith': 'cmd.exe', 'ParentImage|endswith': 'explorer.exe'}",
        ),
        (
            POWERSHELL,
            "powershell",
            "4104",
            "{EventID: 4104, ScriptBlockText: 'Write-Output synthetic'}",
        ),
    ] {
        let variant = table
            .variants
            .iter()
            .find(|variant| {
                variant.product.as_deref() == Some("windows")
                    && variant.service.as_deref() == Some(service)
                    && variant
                        .events
                        .iter()
                        .any(|event| event.values().contains(&SigmaLiteral::Text(id.into())))
            })
            .unwrap();
        let rule = format!(
            "title: Synthetic EVTX row\nlogsource: {{product: windows, service: {service}}}\ndetection: {{selection: {selection}, condition: selection}}\n"
        );
        let rows = raw_rows(fixture).collect::<Vec<_>>();
        let result = rows
            .iter()
            .map(|raw| match_count(variant, raw, &rule))
            .sum::<usize>();
        assert_eq!(result, 1, "{service}");
        let mut wrong_channel = rows
            .iter()
            .find(|raw| raw["Event"]["System"]["EventID"] == id)
            .unwrap()
            .clone();
        wrong_channel["Event"]["System"]["Channel"] = "Other".into();
        assert_eq!(match_count(variant, &wrong_channel, &rule), 0, "{service}");
    }
}

#[test]
fn sigma_windows_without_an_enrolled_channel_skips_the_rule() {
    let table = windows_table();
    let rule = b"title: Synthetic unknown channel\nlogsource: {product: windows, service: unreviewed}\ndetection: {selection: {EventID: 1}, condition: selection}\n";
    for variant in table
        .variants
        .iter()
        .filter(|variant| variant.product.as_deref() == Some("windows"))
    {
        let programs = SigmaVariantPrograms::compile(
            variant,
            [(
                SigmaRuleKeyV1 {
                    id: "synthetic-unknown-channel".into(),
                    sha256: irmind_app::sha256(rule),
                },
                rule.as_slice(),
            )],
        )
        .unwrap();
        assert_eq!(programs.eligible(), 0);
        assert_eq!(
            programs.skipped()[0].1,
            SigmaCoverageV1::UnsupportedLogsource
        );
    }
}

#[test]
fn sigma_sysmon_image_load_and_registry_require_the_reviewed_event_shape() {
    let table = windows_table();
    let source = raw_rows(SYSMON).next().unwrap();
    for (class, event_id, event_type, field, selection) in [
        (
            "image_load",
            "7",
            "ImageLoad",
            "ImageLoaded",
            "'ImageLoaded|endswith': 'synthetic.dll'",
        ),
        (
            "registry_add",
            "12",
            "CreateKey",
            "TargetObject",
            "'TargetObject|endswith': 'synthetic.dll'",
        ),
        (
            "registry_delete",
            "12",
            "DeleteKey",
            "TargetObject",
            "'TargetObject|endswith': 'synthetic.dll'",
        ),
        (
            "registry_rename",
            "14",
            "RenameKey",
            "NewName",
            "'NewName|endswith': 'synthetic.dll'",
        ),
    ] {
        let variant = table
            .variants
            .iter()
            .find(|variant| {
                variant.service.as_deref() == Some("sysmon")
                    && variant.category.as_deref() == Some(class)
            })
            .unwrap();
        let rule = format!(
            "title: Synthetic Sysmon class\nlogsource: {{product: windows, category: {class}}}\ndetection: {{selection: {{{selection}}}, condition: selection}}\n"
        );
        let mut row = source.clone();
        row["Event"]["System"]["EventID"] = event_id.into();
        row["Event"]["EventData"][field] = r"C:\Synthetic\synthetic.dll".into();
        row["Event"]["EventData"]["EventType"] = event_type.into();
        assert_eq!(match_count(variant, &row, &rule), 1, "{class}");

        let mut wrong_event = row.clone();
        if event_id == "12" {
            wrong_event["Event"]["EventData"]["EventType"] = if event_type == "CreateKey" {
                "DeleteKey".into()
            } else {
                "CreateKey".into()
            };
        } else {
            wrong_event["Event"]["System"]["EventID"] = "13".into();
        }
        assert_eq!(match_count(variant, &wrong_event, &rule), 0, "{class}");

        row["Event"]["System"]["Provider"]["#attributes"]["Name"] = "Other".into();
        assert_eq!(match_count(variant, &row, &rule), 0, "{class}");
    }
}
