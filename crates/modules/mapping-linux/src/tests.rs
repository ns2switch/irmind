use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata},
};
use irmind_domain::{CommonField as F, EntityRole, EventCategory, EventOutcome, SourceReferenceV1};
fn decode(raw: &str) -> Vec<SourceRecordV1> {
    let cancel = CancellationToken::new();
    let mut rows = vec![];
    let report = irmind_mod_parser_linux::LinuxSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &SourceReferenceV1::file("synthetic.log").unwrap(),
                    evidence_hash: irmind_app::sha256(raw.as_bytes()),
                    time_context: None,
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(raw.as_bytes()),
            },
            &mut |r| {
                r.inspect(|r| rows.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(report.rejected, 0);
    rows
}
#[test]
fn bundled_tables_have_pinned_canonical_digests() {
    for (source, mapper) in [
        (
            include_str!("sshd.toml"),
            Box::new(SshdMapping::new().unwrap()) as Box<dyn SourceMapper>,
        ),
        (
            include_str!("sudo.toml"),
            Box::new(SudoMapping::new().unwrap()),
        ),
        (include_str!("su.toml"), Box::new(SuMapping::new().unwrap())),
        (
            include_str!("http.toml"),
            Box::new(HttpMapping::new().unwrap()),
        ),
    ] {
        assert!(TableMapping::review(source).unwrap() == *mapper.manifest());
    }
}
#[test]
fn ssh_known_results_missing_state_and_original_source_are_distinct() {
    let mapper = SshdMapping::new().unwrap();
    for (message, outcome) in [
        (
            "Accepted password for alice from 203.0.113.77 port 22 ssh2",
            EventOutcome::Success,
        ),
        (
            "Failed password for alice from 203.0.113.77 port 22 ssh2",
            EventOutcome::Failure,
        ),
        ("Connection closed by 203.0.113.77", EventOutcome::Unknown),
    ] {
        let raw = format!("2026-11-01T00:00:00.123456Z host-a sshd[42]: {message}\n");
        let source = decode(&raw).remove(0);
        let output = mapper.map(&source).unwrap();
        assert_eq!(output.record().common.event().outcome(), outcome);
        assert!(output.record().indexed.record.text.contains(message));
        assert_eq!(source.annotations().raw(), Some(raw.trim_end()));
        assert!(source.fields().field("outcome").is_none());
        assert_eq!(output.record().common.origin(), source.origin());
        assert_eq!(output.record().common.timestamp(), source.timestamp());
    }
}
#[test]
fn pam_missing_actor_and_sudo_command_do_not_invent_authentication_success() {
    let su = SuMapping::new().unwrap();
    let rows = decode(
        "2026-11-01T00:00:00Z host-a su[42]: pam_unix(su:session): session opened for user root by (uid=1000)\n",
    );
    let out = su.map(&rows[0]).unwrap();
    assert_eq!(out.record().common.event().outcome(), EventOutcome::Success);
    assert!(out.record().common.context().get(F::UserName).is_none());
    assert!(
        out.record()
            .common
            .context()
            .get(F::UserTargetName)
            .is_some()
    );
    let sudo = SudoMapping::new().unwrap();
    let rows = decode(
        "2026-11-01T00:00:00Z host-a sudo[42]: alice : TTY=pts/0 ; PWD=/synthetic ; USER=root ; COMMAND=/usr/bin/id\n",
    );
    let out = sudo.map(&rows[0]).unwrap();
    assert_eq!(out.record().common.event().outcome(), EventOutcome::Unknown);
    assert!(
        out.record()
            .common
            .event()
            .categories()
            .contains(EventCategory::Process)
    );
    let observations = out.record().common.observations().values();
    assert!(
        observations
            .iter()
            .any(|o| o.role() == EntityRole::Actor && o.entity().value() == "alice")
    );
    assert!(
        observations
            .iter()
            .any(|o| o.role() == EntityRole::Target && o.entity().value() == "root")
    );
}
#[test]
fn same_user_in_two_roles_and_pid_reuse_have_their_own_identities() {
    let mapper = SudoMapping::new().unwrap();
    let rows = decode(
        "2026-11-01T00:00:00Z host-a sudo[42]: root : USER=root ; COMMAND=/usr/bin/id\n2026-11-01T00:00:01Z host-a sudo[42]: root : USER=root ; COMMAND=/usr/bin/id\n2026-11-01T00:00:02Z host-b sudo[42]: root : USER=root ; COMMAND=/usr/bin/id\n",
    );
    let outputs = rows
        .iter()
        .map(|s| mapper.map(s).unwrap())
        .collect::<Vec<_>>();
    let user = |i: usize, role| {
        outputs[i]
            .record()
            .common
            .observations()
            .values()
            .iter()
            .find(|o| {
                o.role() == role
                    && o.field()
                        == if role == EntityRole::Actor {
                            F::UserName
                        } else {
                            F::UserTargetName
                        }
            })
            .unwrap()
            .entity()
            .clone()
    };
    assert_eq!(user(0, EntityRole::Actor), user(0, EntityRole::Target));
    assert_ne!(user(0, EntityRole::Actor), user(2, EntityRole::Actor));
    let process = |i: usize| {
        outputs[i]
            .record()
            .common
            .observations()
            .values()
            .iter()
            .find(|o| o.field() == F::ProcessPid)
            .unwrap()
            .entity()
            .clone()
    };
    assert_ne!(process(0), process(1));
}
#[test]
fn http_uses_status_ranges_and_retains_dash_as_an_original_marker() {
    let mapper = HttpMapping::new().unwrap();
    for (status, outcome) in [
        (101, EventOutcome::Unknown),
        (200, EventOutcome::Success),
        (403, EventOutcome::Failure),
        (503, EventOutcome::Failure),
    ] {
        let source = decode(&format!("203.0.113.77 - - [01/Nov/2026:00:00:00 +0000] \"GET /synthetic HTTP/1.1\" {status} 12\n")).remove(0);
        assert_eq!(
            source.fields().field("remote_user").unwrap().as_text(),
            Some("-")
        );
        let output = mapper.map(&source).unwrap();
        assert_eq!(output.record().common.event().outcome(), outcome);
        assert!(output.record().common.context().get(F::UserName).is_none());
    }
}
#[test]
fn audit_explicit_outcomes_and_partial_groups_keep_precise_source_time() {
    let mapper = AuditMapping::new().unwrap();
    for (success, ended, outcome) in [
        (Some("yes"), true, EventOutcome::Success),
        (Some("no"), true, EventOutcome::Failure),
        (None, true, EventOutcome::Unknown),
        (Some("yes"), false, EventOutcome::Unknown),
    ] {
        let success = success.map_or_else(String::new, |s| format!("success={s} "));
        let end = if ended {
            "type=EOE msg=audit(1793491200.123456789:1):\n"
        } else {
            ""
        };
        let source = decode(&format!("type=SYSCALL msg=audit(1793491200.123456789:1): {success}syscall=59 uid=1000 euid=0 pid=42 ppid=1 comm=\"synthetic\" exe=\"/synthetic/tool\"\ntype=EXECVE msg=audit(1793491200.123456789:1): argc=1 a0=\"synthetic\"\n{end}")).remove(0);
        let output = mapper.map(&source).unwrap();
        assert_eq!(output.record().common.event().outcome(), outcome);
        assert_eq!(
            output
                .record()
                .common
                .timestamp()
                .unwrap()
                .instant()
                .submicro_nanos(),
            789
        );
        assert!(
            output
                .record()
                .common
                .event()
                .categories()
                .contains(EventCategory::Process)
        );
    }
}

#[test]
fn every_module_passes_the_shared_contract_and_frozen_catalog_is_unambiguous() {
    use irmind_app::source_mapping::MappingCatalog;
    type Entry = (Arc<dyn SourceMapper>, &'static [u8]);
    let entries: Vec<Entry> = vec![
        (
            Arc::new(SshdMapping::new().unwrap()),
            include_bytes!("../../../testkit/fixtures/common/linux/sshd.log"),
        ),
        (
            Arc::new(SudoMapping::new().unwrap()),
            include_bytes!("../../../testkit/fixtures/common/linux/sudo.log"),
        ),
        (
            Arc::new(SuMapping::new().unwrap()),
            include_bytes!("../../../testkit/fixtures/common/linux/su.log"),
        ),
        (
            Arc::new(HttpMapping::new().unwrap()),
            include_bytes!("../../../testkit/fixtures/common/linux/http.log"),
        ),
        (
            Arc::new(AuditMapping::new().unwrap()),
            include_bytes!("../../../testkit/fixtures/common/linux/auditd.log"),
        ),
    ];
    let decoder: Arc<dyn SourceDecoder> = Arc::new(irmind_mod_parser_linux::LinuxSourceDecoder);
    let catalog = MappingCatalog::freeze(
        vec![decoder.clone()],
        entries.iter().map(|(m, _)| m.clone()).collect(),
    )
    .unwrap();
    assert_eq!(catalog.snapshots().unwrap().len(), 5);
    for (mapper, bytes) in entries {
        irmind_testkit::run_source_mapping_contract(
            decoder.clone(),
            mapper,
            "synthetic.log",
            bytes,
            3,
        )
        .unwrap();
    }
}

#[test]
fn each_mapping_is_its_own_module_with_one_declared_port() {
    use irmind_app::modules::ModuleRegistry;
    let mut registry = ModuleRegistry::new();
    let config = ModuleConfig::new();
    registry
        .register(
            Box::<irmind_mod_parser_linux::LinuxParser>::default(),
            &config,
        )
        .unwrap();
    registry
        .register(Box::new(SshdMapping::new().unwrap()), &config)
        .unwrap();
    registry
        .register(Box::new(SudoMapping::new().unwrap()), &config)
        .unwrap();
    registry
        .register(Box::new(SuMapping::new().unwrap()), &config)
        .unwrap();
    registry
        .register(Box::new(HttpMapping::new().unwrap()), &config)
        .unwrap();
    registry
        .register(Box::new(AuditMapping::new().unwrap()), &config)
        .unwrap();
    assert_eq!(
        registry
            .mapping_catalog()
            .unwrap()
            .snapshots()
            .unwrap()
            .len(),
        5
    );
}

#[test]
fn invalid_extracted_values_are_errors_instead_of_unfiltered_or_empty_mappings() {
    let mapper = SshdMapping::new().unwrap();
    for message in [
        "Failed password for alice from not-an-ip port 22 ssh2",
        "Failed password for alice from 203.0.113.77 port 999999 ssh2",
        "Failed password for alice from 203.0.113.77 port -1 ssh2",
    ] {
        let source = decode(&format!(
            "2026-11-01T00:00:00Z host-a sshd[42]: {message}\n"
        ))
        .remove(0);
        assert!(mapper.map(&source).is_err());
    }
}

#[test]
fn audit_actor_and_target_are_explicit_and_multiple_syscalls_are_not_guessed() {
    let mapper = AuditMapping::new().unwrap();
    let source = decode("node=host-a type=SYSCALL msg=audit(1793491200.123:1): syscall=59 success=no uid=1000 obj_uid=1001 pid=42\nnode=host-a type=EOE msg=audit(1793491200.123:1):\n").remove(0);
    let output = mapper.map(&source).unwrap();
    let roles = output.record().common.observations().values();
    assert!(
        roles
            .iter()
            .any(|o| o.role() == EntityRole::Actor && o.entity().value() == "1000")
    );
    assert!(
        roles
            .iter()
            .any(|o| o.role() == EntityRole::Target && o.entity().value() == "1001")
    );
    let source = decode("type=SYSCALL msg=audit(1793491200.123:1): syscall=59 success=yes uid=1000 pid=42\ntype=SYSCALL msg=audit(1793491200.123:1): syscall=59 success=no uid=0 pid=42\ntype=EOE msg=audit(1793491200.123:1):\n").remove(0);
    assert!(mapper.map(&source).is_err());
}

#[test]
fn unsupported_audit_member_types_stay_unclassified_regardless_of_message_text() {
    let source = decode("type=USER_AUTH msg=audit(1793491200.123:1): res=failed op=\"authentication failed\"\ntype=EOE msg=audit(1793491200.123:1):\n").remove(0);
    let output = AuditMapping::new().unwrap().map(&source).unwrap();
    assert_eq!(
        output.record().common.event(),
        &irmind_domain::EventHeaderV1::default()
    );
}

#[test]
fn every_included_linux_process_observation_uses_source_record_scope() {
    use irmind_domain::{EntityIdentityScope, ObservedEntityKind};
    let fixtures: Vec<(Box<dyn SourceMapper>, &str)> = vec![
        (
            Box::new(SshdMapping::new().unwrap()),
            include_str!("../../../testkit/fixtures/common/linux/sshd.log"),
        ),
        (
            Box::new(SudoMapping::new().unwrap()),
            include_str!("../../../testkit/fixtures/common/linux/sudo.log"),
        ),
        (
            Box::new(SuMapping::new().unwrap()),
            include_str!("../../../testkit/fixtures/common/linux/su.log"),
        ),
        (
            Box::new(HttpMapping::new().unwrap()),
            include_str!("../../../testkit/fixtures/common/linux/http.log"),
        ),
        (
            Box::new(AuditMapping::new().unwrap()),
            include_str!("../../../testkit/fixtures/common/linux/auditd.log"),
        ),
    ];
    let mut checked = 0;
    for (mapper, fixture) in fixtures {
        let mut per_mapping = 0;
        for source in decode(fixture) {
            if !mapper
                .manifest()
                .selectors()
                .iter()
                .any(|s| s.matches(&source))
            {
                continue;
            }
            let output = mapper.map(&source).unwrap();
            for observation in output
                .record()
                .common
                .observations()
                .values()
                .iter()
                .filter(|o| o.entity().kind() == ObservedEntityKind::Process)
            {
                assert!(matches!(
                    observation.entity().scope(),
                    EntityIdentityScope::SourceRecord { .. }
                ));
                checked += 1;
                per_mapping += 1;
            }
        }
        if mapper.manifest().identity().id() != "mapping-linux-http" {
            assert!(per_mapping > 0, "{}", mapper.manifest().identity().id());
        }
    }
    assert!(checked > 0);
}
