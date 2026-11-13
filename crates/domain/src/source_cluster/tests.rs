use super::*;
use std::fmt::Write as _;
fn identity(id: &str) -> ClusterIdentity {
    ClusterIdentity::try_new(ClusterProvider::Kubernetes, id).unwrap()
}
pub(crate) fn context() -> SourceClusterContext {
    SourceClusterContext::try_new(vec![
        SourceClusterBinding::try_new(
            identity("urn:k8s:lab-a"),
            ClusterContextBasis::Analyst,
            None,
        )
        .unwrap(),
    ])
    .unwrap()
}
#[test]
fn cluster_context_is_bounded_canonical_and_has_fixed_codes() {
    let context = context();
    let bytes = context.encode();
    assert_eq!(SourceClusterContext::decode(&bytes).unwrap(), context);
    let mut hex = String::new();
    for byte in &bytes {
        write!(&mut hex, "{byte:02x}").unwrap();
    }
    assert_eq!(hex, include_str!("context-v1.hex").trim());
    assert_eq!(context.resolve(None).unwrap().id(), "urn:k8s:lab-a");
    assert!(context.resolve(Some(&identity("urn:k8s:lab-b"))).is_err());
    let mut invalid = bytes.clone();
    invalid.push(0);
    assert!(SourceClusterContext::decode(&invalid).is_err());
    for end in 0..bytes.len() {
        assert!(SourceClusterContext::decode(&bytes[..end]).is_err());
    }
    for bad in [
        "",
        "x",
        " urn:k8s:a",
        "urn:k8s:a ",
        "urn:k8s:../a",
        "urn:k8s:a\n",
        "urn:k8s:a\u{202e}",
        "urn:k8s:*",
        "urn:k8s:a?token=secret",
    ] {
        assert!(
            ClusterIdentity::try_new(ClusterProvider::Kubernetes, bad).is_err(),
            "{bad:?}"
        );
    }
    assert!(
        ClusterIdentity::try_new(
            ClusterProvider::Kubernetes,
            &format!("urn:k8s:{}", "x".repeat(512))
        )
        .is_err()
    );
    assert!(SourceClusterContext::try_new(vec![]).is_err());
    assert!(SourceClusterContext::try_new(vec![context.bindings()[0].clone(); 9]).is_err());
    let other_provider = ClusterIdentity::try_new(ClusterProvider::Eks, "urn:k8s:lab-a").unwrap();
    assert_ne!(
        context.bindings()[0].identity().qualified(),
        other_provider.qualified()
    );
    assert_eq!(
        ClusterIdentity::parse_qualified(&other_provider.qualified()).unwrap(),
        other_provider
    );
}
#[test]
fn confirmed_claims_are_exact_ordered_and_never_choose_an_implicit_default() {
    let binding = |id: &str| {
        SourceClusterBinding::try_new(identity(id), ClusterContextBasis::ConfirmedSource, Some(id))
            .unwrap()
    };
    let a = binding("urn:k8s:a");
    let b = binding("urn:k8s:b");
    let first = SourceClusterContext::try_new(vec![a.clone(), b.clone()]).unwrap();
    let second = SourceClusterContext::try_new(vec![b, a.clone()]).unwrap();
    assert_eq!(first.encode(), second.encode());
    assert!(first.resolve(None).is_err());
    assert_eq!(first.resolve(Some(a.identity())).unwrap(), a.identity());
    assert!(
        SourceClusterBinding::try_new(
            identity("urn:k8s:a"),
            ClusterContextBasis::ConfirmedSource,
            Some("urn:k8s:b")
        )
        .is_err()
    );
    assert!(SourceClusterContext::try_new(vec![a.clone(), a]).is_err());
    let mut noncanonical = first.encode();
    let header = b"irmind-source-cluster-context-v1\0".len() + 1;
    let entry = (noncanonical.len() - header) / 2;
    let (left, right) = noncanonical[header..].split_at_mut(entry);
    left.swap_with_slice(right);
    assert!(SourceClusterContext::decode(&noncanonical).is_err());
}
#[test]
fn signed_source_and_record_set_bind_context_without_changing_absent_encoding() {
    let source = crate::SourceManifestV1 {
        source: "audit.json".into(),
        size: 42,
        modified_unix_seconds: None,
        version: None,
        provider_checksum: None,
        sha256: crate::EvidenceHash::from_bytes([1; 32]),
        copied: false,
    };
    let mut manifest = crate::SourceManifestV2 {
        source,
        parser_id: "parser-kubernetes".into(),
        parser_version: "kubernetes-source-v1".into(),
        confidence: 100,
        selection: crate::ParserSelectionMode::Analyst,
        timestamp_context: None,
        cluster_context: None,
        rejected_records: 0,
        rejected_sample: vec![],
    };
    let absent = manifest.encode().unwrap();
    assert_eq!(crate::SourceManifestV2::decode(&absent).unwrap(), manifest);
    manifest.cluster_context = Some(context());
    let encoded = manifest.encode().unwrap();
    assert_ne!(encoded, absent);
    assert_eq!(encoded, include_str!("source-manifest-v1.hex").trim());
    assert_eq!(crate::SourceManifestV2::decode(&encoded).unwrap(), manifest);
    // The context descriptor is checked independently of the surrounding signature.
    let mut changed = encoded.clone();
    let tail = changed.pop().unwrap();
    changed.push(if tail == '0' { '1' } else { '0' });
    assert!(crate::SourceManifestV2::decode(&changed).is_err());
    let set = crate::SourceRecordSetV1::from_manifest(
        &manifest,
        crate::SourceReferenceV1::file("audit.json").unwrap(),
        vec![crate::SourceFormatIdentityV1::try_new("kubernetes-audit", "v1").unwrap()],
        1,
        crate::EvidenceHash::from_bytes([2; 32]),
    )
    .unwrap();
    assert_eq!(set.cluster_context(), manifest.cluster_context.as_ref());
    assert_eq!(
        set.encode().unwrap(),
        include_str!("source-set-v1.hex").trim()
    );
    assert!(crate::SourceRecordSetV1::decode(&set.encode().unwrap()).unwrap() == set);
    set.validate_manifest(&manifest).unwrap();
    manifest.cluster_context = None;
    assert!(set.validate_manifest(&manifest).is_err());
}

#[test]
fn cluster_wire_enumerations_are_fixed_and_unknown_codes_are_rejected() {
    let header = b"irmind-source-cluster-context-v1\0".len() + 1;
    for (provider, provider_code) in [
        (ClusterProvider::Kubernetes, 0),
        (ClusterProvider::Eks, 1),
        (ClusterProvider::Gke, 2),
        (ClusterProvider::Aks, 3),
    ] {
        for (basis, basis_code) in [
            (ClusterContextBasis::Analyst, 0),
            (ClusterContextBasis::Command, 1),
            (ClusterContextBasis::ConfirmedSource, 2),
        ] {
            let claim =
                (basis == ClusterContextBasis::ConfirmedSource).then_some("urn:k8s:synthetic");
            let binding = SourceClusterBinding::try_new(
                ClusterIdentity::try_new(provider, "urn:k8s:synthetic").unwrap(),
                basis,
                claim,
            )
            .unwrap();
            let context = SourceClusterContext::try_new(vec![binding]).unwrap();
            let mut encoded = context.encode();
            assert_eq!(&encoded[header..header + 2], &[provider_code, basis_code]);
            assert_eq!(SourceClusterContext::decode(&encoded).unwrap(), context);
            encoded[header] = 255;
            assert!(SourceClusterContext::decode(&encoded).is_err());
        }
    }
    let mut encoded = context().encode();
    encoded[header + 1] = 255;
    assert!(SourceClusterContext::decode(&encoded).is_err());
}
