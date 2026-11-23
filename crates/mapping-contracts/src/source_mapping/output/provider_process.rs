use crate::source_mapping::{SourceRecordV1, SourceValue};
use irmind_domain::{CommonEventV1, CommonField, EntityIdentityScope};

pub(super) fn valid(
    source: &SourceRecordV1,
    common: &CommonEventV1,
    partition: &super::MappingPartition,
) -> bool {
    common.observations().values().iter().all(|observation| {
        let EntityIdentityScope::ProviderProcess {
            provider,
            tenant,
            host,
        } = observation.entity().scope()
        else {
            return true;
        };
        if partition.profile() != crate::PartitionProfile::EndpointHost
            || partition.host() != host.as_str()
            || provider.as_str() != "crowdstrike-fdr"
            || source.origin().parser() != "parser-fdr"
            || source.origin().parser_version() != "fdr-source-v1"
            || source.format().id() != "falcon-fdr"
            || source.format().version() != "fdr-source-v1"
        {
            return false;
        }
        let fields = source.fields();
        if fields.field("cid").and_then(SourceValue::as_text) != Some(tenant.as_str())
            || fields.field("aid").and_then(SourceValue::as_text) != Some(host.as_str())
        {
            return false;
        }
        let Some(event) = fields
            .field("event_simpleName")
            .and_then(SourceValue::as_text)
        else {
            return false;
        };
        let key = match (event, observation.field()) {
            ("ProcessRollup2" | "SyntheticProcessRollup2", CommonField::ProcessEntityId) => {
                "TargetProcessId"
            }
            ("ProcessRollup2" | "SyntheticProcessRollup2", CommonField::ProcessParentEntityId) => {
                "ParentProcessId"
            }
            (
                "NetworkConnectIP4" | "NetworkConnectIP6" | "NetworkListenIP4" | "NetworkListenIP6"
                | "DnsRequest" | "UserLogon" | "UserLogonFailed2",
                CommonField::ProcessEntityId,
            ) => "ContextProcessId",
            _ => return false,
        };
        let raw = match fields.field(key) {
            Some(SourceValue::Text(v)) => v.as_str(),
            Some(SourceValue::Number(v)) => v.as_str(),
            _ => return false,
        };
        !raw.is_empty()
            && raw.len() <= 128
            && raw.bytes().all(|b| b.is_ascii_digit())
            && raw
                .parse::<u64>()
                .is_ok_and(|v| v != 0 && v.to_string() == observation.entity().value())
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{
        PartitionProfile,
        source_mapping::{DecodeAnnotationsV1, MappingPartition, SourceFormatV1},
    };
    use irmind_domain::*;
    use std::collections::BTreeMap;
    const TENANT: &str = "00000000000000000000000000000001";
    const HOST: &str = "00000000000000000000000000000100";
    fn source(tenant: &str, id: &str, event: &str, format: &str) -> SourceRecordV1 {
        SourceRecordV1::try_new(
            EventOrigin::try_new(
                EvidenceHash::from_bytes([1; 32]),
                0,
                Some(0),
                "parser-fdr",
                "fdr-source-v1",
            )
            .unwrap(),
            "synthetic.ndjson",
            None,
            SourceFormatV1::try_new(format, "fdr-source-v1", BTreeMap::new()).unwrap(),
            SourceValue::object(vec![
                ("cid".into(), SourceValue::Text(tenant.into())),
                ("aid".into(), SourceValue::Text(HOST.into())),
                ("TargetProcessId".into(), SourceValue::Text(id.into())),
                ("RawProcessId".into(), SourceValue::Text("42".into())),
                ("event_simpleName".into(), SourceValue::Text(event.into())),
            ])
            .unwrap(),
            DecodeAnnotationsV1::default(),
        )
        .unwrap()
    }
    fn common(source: &SourceRecordV1) -> CommonEventV1 {
        let scope = EntityIdentityScope::provider_process(
            ProcessIdentityProvider::CrowdStrikeFdr,
            TENANT,
            HOST,
        )
        .unwrap();
        let entity = ObservedEntity::try_new(ObservedEntityKind::Process, "42", scope).unwrap();
        let observation =
            EntityObservation::try_new(entity, EntityRole::Subject, CommonField::ProcessEntityId)
                .unwrap();
        let mut context = EventContextV1::default();
        context
            .try_insert(
                CommonField::HostId,
                CommonValue::Text(EventText::new(HOST).unwrap()),
            )
            .unwrap();
        context
            .try_insert(
                CommonField::ProcessEntityId,
                CommonValue::Text(EventText::new("42").unwrap()),
            )
            .unwrap();
        CommonEventV1::try_new(
            source.origin().clone(),
            source.timestamp(),
            EventHeaderV1::default(),
            context,
            BoundedObservations::try_new(vec![observation]).unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn provider_process_original_fields_and_partition_must_match_the_signed_claim() {
        let partition =
            MappingPartition::try_new(PartitionProfile::EndpointHost, "", "", HOST).unwrap();
        let good = source(TENANT, "00042", "ProcessRollup2", "falcon-fdr");
        assert!(valid(&good, &common(&good), &partition));
        for bad in [
            source(
                "00000000000000000000000000000002",
                "42",
                "ProcessRollup2",
                "falcon-fdr",
            ),
            source(TENANT, "43", "ProcessRollup2", "falcon-fdr"),
            source(TENANT, "42", "UnknownEvent", "falcon-fdr"),
            source(TENANT, "42", "ProcessRollup2", "other-format"),
        ] {
            assert!(!valid(&bad, &common(&bad), &partition));
        }
        assert!(!valid(&good, &common(&good), &MappingPartition::default()));
        let other = MappingPartition::try_new(PartitionProfile::EndpointHost, "", "", "other-host")
            .unwrap();
        assert!(!valid(&good, &common(&good), &other));
    }
}
