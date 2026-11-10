use super::*;

#[test]
fn sysmon_lifetime_uses_only_reported_guid_and_pid_reuse_stays_separate() {
    let mapper = SysmonMapping::new().unwrap();
    let raw = original(&sources("sysmon")[0]);
    let first = mapper.map(&source(0, &raw)).unwrap();
    let mut next = raw.clone();
    next["Event"]["EventData"]["ProcessGuid"] = json!("{00000000-0000-0000-0000-000000000099}");
    let second = mapper.map(&source(1, &next)).unwrap();
    let process = |out: &MappingOutput| {
        out.record()
            .common
            .observations()
            .values()
            .iter()
            .find(|o| o.field() == F::ProcessEntityId)
            .unwrap()
            .entity()
            .clone()
    };
    assert_ne!(process(&first), process(&second));
    assert!(matches!(
        process(&first).scope(),
        EntityIdentityScope::ProcessLifetime { .. }
    ));
    let mut missing = raw;
    missing["Event"]["EventData"]
        .as_object_mut()
        .unwrap()
        .remove("ProcessGuid");
    let missing = mapper.map(&source(2, &missing)).unwrap();
    assert!(
        missing
            .record()
            .common
            .observations()
            .values()
            .iter()
            .all(|o| o.role() != EntityRole::Subject
                || o.entity().kind() != irmind_domain::ObservedEntityKind::Process)
    );
    let security = SecurityMapping::new(4688)
        .unwrap()
        .map(&sources("security")[5])
        .unwrap();
    assert!(
        security
            .record()
            .common
            .observations()
            .values()
            .iter()
            .filter(|o| o.entity().kind() == irmind_domain::ObservedEntityKind::Process)
            .all(|o| matches!(o.entity().scope(), EntityIdentityScope::SourceRecord { .. }))
    );
}
#[test]
fn same_name_keeps_both_roles_and_separate_reported_directory_namespaces() {
    let mapper = SecurityMapping::new(4625).unwrap();
    let mut raw = original(&sources("security")[1]);
    raw["Event"]["EventData"]["SubjectUserName"] = json!("alice");
    raw["Event"]["EventData"]["SubjectDomainName"] = json!("REALM-A");
    raw["Event"]["EventData"]["TargetDomainName"] = json!("REALM-B");
    let out = mapper.map(&source(0, &raw)).unwrap();
    let actor = out
        .record()
        .common
        .observations()
        .values()
        .iter()
        .find(|o| o.field() == F::UserName)
        .unwrap();
    let target = out
        .record()
        .common
        .observations()
        .values()
        .iter()
        .find(|o| o.field() == F::UserTargetName)
        .unwrap();
    assert_eq!(actor.entity().value(), target.entity().value());
    assert_ne!(actor.entity(), target.entity());
    raw["Event"]["EventData"]["TargetDomainName"] = json!("REALM-A");
    let out = mapper.map(&source(0, &raw)).unwrap();
    let actor = out
        .record()
        .common
        .observations()
        .values()
        .iter()
        .find(|o| o.field() == F::UserName)
        .unwrap();
    let target = out
        .record()
        .common
        .observations()
        .values()
        .iter()
        .find(|o| o.field() == F::UserTargetName)
        .unwrap();
    assert_eq!(actor.entity(), target.entity());
    assert_ne!(actor.role(), target.role());
}

#[test]
fn successful_logon_and_group_membership_keep_event_specific_roles() {
    let logon = SecurityMapping::new(4624)
        .unwrap()
        .map(&sources("security")[0])
        .unwrap();
    assert!(
        logon
            .record()
            .common
            .observations()
            .values()
            .iter()
            .any(|o| o.field() == F::UserName
                && o.role() == EntityRole::Actor
                && o.entity().value() == "alice")
    );
    assert!(
        logon
            .record()
            .common
            .observations()
            .values()
            .iter()
            .any(|o| o.field() == F::SourceUserName
                && o.role() == EntityRole::Source
                && o.entity().value() == "operator")
    );
    for id in [4728, 4732, 4756] {
        let row = sources("security").remove(
            SecurityMapping::EVENT_IDS
                .iter()
                .position(|n| *n == id)
                .unwrap(),
        );
        let out = SecurityMapping::new(id).unwrap().map(&row).unwrap();
        assert!(
            out.record()
                .common
                .observations()
                .values()
                .iter()
                .any(|o| o.field() == F::UserTargetId && o.entity().value() == "S-1-5-21-1002")
        );
        assert!(
            out.record()
                .common
                .observations()
                .values()
                .iter()
                .any(|o| o.field() == F::IrmindResourceId && o.entity().value() == "S-1-5-32-544")
        );
        assert!(
            out.record()
                .common
                .observations()
                .values()
                .iter()
                .all(|o| o.entity().value() != "Synthetic Operators")
        );
    }
}
