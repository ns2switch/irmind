//! Organization-owned source-query settings. Secrets are resolved only from the keystore.
use anyhow::Result;
use irmind_app::{
    AppError, Clock, SecretBackend, SourceMapper,
    source_queries::{
        ResolvedQuerySourceV1, SourceQueryAllocationV1, SourceQueryError, SourceQueryExecutor,
        SourceQueryLimits, SourceQueryPageDecoder, SourceQueryPorts,
    },
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceQuerySettings {
    pub(crate) case_ceiling: SourceQueryAllocationV1,
    sources: Vec<ConfiguredQuerySource>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfiguredQuerySource {
    source: ResolvedQuerySourceV1,
    limits: SourceQueryLimits,
    scan_approval_threshold: Option<u64>,
    native: Native,
}

#[derive(Deserialize)]
#[serde(tag = "module", deny_unknown_fields)]
enum Native {
    #[serde(rename = "query-athena")]
    Athena {
        workgroup: String,
        allow_cutoff_overrun: bool,
    },
    #[serde(rename = "query-bigquery")]
    BigQuery,
    #[serde(rename = "query-azure-log-analytics")]
    Analytics {
        subscription: String,
        resource_group: String,
        workspace_name: String,
    },
}

impl Native {
    fn name(&self) -> &'static str {
        match self {
            Self::Athena { .. } => "query-athena",
            Self::BigQuery => "query-bigquery",
            Self::Analytics { .. } => "query-azure-log-analytics",
        }
    }

    fn compiled(&self) -> bool {
        match self {
            Self::Athena { .. } => cfg!(feature = "query-athena"),
            Self::BigQuery => cfg!(feature = "query-bigquery"),
            Self::Analytics { .. } => cfg!(feature = "query-azure-log-analytics"),
        }
    }

    fn valid(&self) -> bool {
        let identifier = irmind_app::source_queries::native_identifier;
        match self {
            Self::Athena {
                workgroup,
                allow_cutoff_overrun,
            } => *allow_cutoff_overrun && identifier(workgroup) && workgroup != "primary",
            Self::BigQuery => true,
            Self::Analytics {
                subscription,
                resource_group,
                workspace_name,
            } => [subscription, resource_group, workspace_name]
                .iter()
                .all(|name| identifier(name)),
        }
    }
}

struct QueryImplementation {
    executor: Arc<dyn SourceQueryExecutor>,
    decoder: Arc<dyn SourceQueryPageDecoder>,
    mapper: Box<dyn SourceMapper>,
}

impl SourceQuerySettings {
    pub(crate) fn validate(&self, scope: &irmind_domain::CaseScope) -> Result<()> {
        self.case_ceiling.validate()?;
        let mut ids = std::collections::BTreeSet::new();
        if !self.case_ceiling.enabled || self.sources.is_empty() || self.sources.len() > 64 {
            return Err(SourceQueryError::Invalid.into());
        }
        for item in &self.sources {
            item.limits.validate()?;
            let analytics = matches!(item.native, Native::Analytics { .. });
            let source = &item.source;
            let owned = match item.native {
                Native::BigQuery => scope.allows_project(source.id(), source.owner()),
                _ => scope.allows_account(source.id(), source.owner()),
            };
            if !item.native.valid()
                || !owned
                || item.scan_approval_threshold.is_some_and(|threshold| {
                    item.limits
                        .scan_bytes
                        .is_none_or(|maximum| threshold > maximum)
                })
                || !ids.insert(item.source.id())
                || item.source.module() != item.native.name()
                || item.limits.scan_bytes.is_none() != analytics
                || (analytics && !self.case_ceiling.analytics_allowed)
                || item.limits.rows > self.case_ceiling.retained_rows
                || item.limits.retained_bytes > self.case_ceiling.retained_bytes
                || item
                    .limits
                    .scan_bytes
                    .is_some_and(|max| self.case_ceiling.scan_bytes.is_none_or(|cap| max > cap))
            {
                return Err(SourceQueryError::Scope.into());
            }
        }
        Ok(())
    }

    pub(crate) fn build(
        &self,
        secrets: &dyn SecretBackend,
        clock: &Arc<dyn Clock>,
    ) -> Result<SourceQueryPorts> {
        let mut ports = SourceQueryPorts::new().with_organization_ceiling(self.case_ceiling)?;
        for item in &self.sources {
            if !item.native.compiled() {
                continue;
            }
            let implementation = match item.implementation(secrets, clock) {
                Ok(implementation) => implementation,
                Err(AppError::SecretMissing) => continue,
                Err(error) => return Err(error.into()),
            };
            ports.register_configured_source(
                item.source.clone(),
                item.limits.clone(),
                implementation.mapper.manifest().identity().clone(),
                implementation.executor,
                implementation.decoder,
            )?;
        }
        Ok(ports)
    }

    pub(crate) fn adoption(&self, source_id: &str) -> Result<Vec<u8>> {
        let item = self
            .sources
            .iter()
            .find(|item| item.source.id() == source_id)
            .ok_or(SourceQueryError::Unavailable)?;
        let source = &item.source;
        let owners = [source.owner()];
        let (accounts, projects, workspaces) = match item.native {
            Native::Athena { .. } => (&owners[..], &[][..], &[][..]),
            Native::BigQuery => (&[][..], &owners[..], &[][..]),
            Native::Analytics { .. } => (&[][..], &[][..], &owners[..]),
        };
        let policy = serde_json::json!({
            "version": 1,
            "source": source,
            "policy": {
                "accounts": accounts, "projects": projects, "workspaces": workspaces,
                "regions": [source.location()], "sources": [source.id()],
                "interval_seconds": item.limits.interval_seconds,
                "query_retained_bytes": item.limits.retained_bytes,
                "query_rows": item.limits.rows,
                "query_scan_bytes": item.limits.scan_bytes,
                "scan_approval_threshold": item.scan_approval_threshold,
            }
        });
        Ok(irmind_app::source_queries::canonical_query_json(&policy)?)
    }

    pub(crate) fn credential_names(&self) -> Vec<String> {
        self.sources
            .iter()
            .filter(|item| item.native.compiled())
            .flat_map(|item| {
                let fields: &[&str] = match item.native {
                    Native::Athena { .. } => &[],
                    Native::BigQuery => &["service-account-json"],
                    Native::Analytics { .. } => &["tenant-id", "client-id", "client-secret"],
                };
                fields.iter().map(move |field| item.credential(field))
            })
            .collect()
    }
}

impl ConfiguredQuerySource {
    fn credential(&self, field: &str) -> String {
        format!("{}/{}/{field}", self.source.module(), self.source.id())
    }
    #[cfg(feature = "query-azure-log-analytics")]
    fn azure_implementation(
        &self,
        secrets: &dyn SecretBackend,
        subscription: &str,
        resource_group: &str,
        workspace_name: &str,
        clock: &Arc<dyn Clock>,
    ) -> Result<QueryImplementation, AppError> {
        use irmind_app::SourceDecoder as _;
        use secrecy::ExposeSecret as _;
        let source = self.source.clone();
        let limits = self.limits.clone();
        let credential =
            |field: &str| secrets.get(&storage_credential_name(&self.credential(field)));
        let decoder =
            irmind_mod_query_azure_log_analytics::AzureAnalyticsCaptureDecoder::for_dataset(
                source.dataset(),
            )?;
        let identity = decoder.identity();
        let identity =
            irmind_domain::SourceDecoderIdentityV1::try_new(identity.name, identity.version)
                .map_err(|_| SourceQueryError::Invalid)?;
        let exec = irmind_mod_query_azure_log_analytics::AzureLogAnalytics::new(
            source,
            limits,
            credential("tenant-id")?.expose_secret(),
            credential("client-id")?.expose_secret(),
            credential("client-secret")?,
            subscription,
            resource_group,
            workspace_name,
            clock.clone(),
        )?;
        Ok(QueryImplementation {
            executor: Arc::new(exec),
            decoder: Arc::new(decoder),
            mapper: Box::new(
                irmind_mod_mapping_entra::EntraMapping::for_capture(
                    decoder.file_format(),
                    &identity,
                )
                .map_err(irmind_app::source_mapping::MappingError::into_app)?,
            ),
        })
    }

    fn implementation(
        &self,
        secrets: &dyn SecretBackend,
        clock: &Arc<dyn Clock>,
    ) -> Result<QueryImplementation, AppError> {
        match &self.native {
            #[cfg(feature = "query-athena")]
            Native::Athena {
                workgroup,
                allow_cutoff_overrun,
            } => {
                use secrecy::ExposeSecret as _;
                let access = secrets.get("AWS_ACCESS_KEY_ID")?;
                let secret = secrets.get("AWS_SECRET_ACCESS_KEY")?;
                let session = match secrets.get("AWS_SESSION_TOKEN") {
                    Ok(token) => Some(token),
                    Err(AppError::SecretMissing) => None,
                    Err(error) => return Err(error),
                };
                let exec = irmind_mod_query_athena::Athena::with_explicit_keys(
                    self.source.clone(),
                    self.limits.clone(),
                    workgroup,
                    access.expose_secret(),
                    secret.expose_secret(),
                    session.as_ref().map(secrecy::ExposeSecret::expose_secret),
                    *allow_cutoff_overrun,
                    clock.clone(),
                )?;
                Ok(QueryImplementation {
                    executor: Arc::new(exec),
                    decoder: Arc::new(irmind_mod_query_athena::AthenaCaptureDecoder),
                    mapper: Box::new(
                        irmind_mod_mapping_cloudtrail::CloudTrailMapping::for_capture()
                            .map_err(irmind_app::source_mapping::MappingError::into_app)?,
                    ),
                })
            }
            #[cfg(feature = "query-bigquery")]
            Native::BigQuery => {
                let exec = irmind_mod_query_bigquery::BigQuery::with_service_account(
                    self.source.clone(),
                    self.limits.clone(),
                    &secrets.get(&storage_credential_name(
                        &self.credential("service-account-json"),
                    ))?,
                    clock.clone(),
                )?;
                Ok(QueryImplementation {
                    executor: Arc::new(exec),
                    decoder: Arc::new(irmind_mod_query_bigquery::BigQueryCaptureDecoder),
                    mapper: Box::new(
                        irmind_mod_mapping_gcp_audit::CloudAuditMapping::for_capture()
                            .map_err(irmind_app::source_mapping::MappingError::into_app)?,
                    ),
                })
            }
            #[cfg(feature = "query-azure-log-analytics")]
            Native::Analytics {
                subscription,
                resource_group,
                workspace_name,
            } => self.azure_implementation(
                secrets,
                subscription,
                resource_group,
                workspace_name,
                clock,
            ),
            #[allow(unreachable_patterns)]
            _ => {
                let _ = (secrets, clock);
                Err(SourceQueryError::Unavailable.into())
            }
        }
    }
}

/// Map configured public identifiers to the existing file-keystore alphabet.
/// The logical provider namespace remains visible in the credential UI.
pub(crate) fn storage_credential_name(name: &str) -> String {
    if !name.contains('/') {
        return name.to_owned();
    }
    let mut domain = b"irmind-source-query-keystore-v1\0".to_vec();
    domain.extend_from_slice(name.as_bytes());
    let digest = irmind_app::hex(&irmind_app::sha256(&domain));
    format!("SQ_{}", digest[..60].to_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use irmind_domain::CaseScope;

    #[test]
    fn configuration_binds_adoption_and_credentials_to_the_source() -> Result<()> {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/development/source-query-format-vectors/plan.json"
        ))?;
        let mut limits = vector["limits"].clone();
        limits["scan_bytes"] = serde_json::json!(64 * 1024 * 1024);
        let settings: SourceQuerySettings = serde_json::from_value(serde_json::json!({
            "case_ceiling": {
                "enabled": true, "analytics_allowed": false, "scan_bytes": 67_108_864,
                "retained_rows": 100_000, "retained_bytes": 100_000_000
            },
            "sources": [{
                "source": {
                    "id": "gcp-audit",
                    "module": "query-bigquery",
                    "module_version": "1",
                    "dataset": "cloud-audit-logs",
                    "owner": "synthetic-project",
                    "location": "EU",
                    "table": "audit.cloudaudit_googleapis_com_activity",
                    "partitions": [{
                        "name":"layout", "type":"text", "value":"timestamp-partitioned"
                    }]
                },
                "limits": limits,
                "scan_approval_threshold": 10_485_760,
                "native": {"module": "query-bigquery"}
            }]
        }))?;
        let scope = CaseScope::parse(
            "v2;sources=gcp-audit;accounts=;projects=synthetic-project;hosts=;from=2026-11-01T00:00:00Z;to=2026-12-01T00:00:00Z",
        ).map_err(|_| anyhow::anyhow!("invalid synthetic organization scope"))?;
        settings.validate(&scope)?;
        assert!(settings.validate(&CaseScope::LocalOnly).is_err());
        assert!(settings.adoption("other-source").is_err());
        let adopted: serde_json::Value = serde_json::from_slice(&settings.adoption("gcp-audit")?)?;
        assert_eq!(adopted["source"]["owner"], "synthetic-project");
        assert_eq!(
            adopted["policy"]["projects"],
            serde_json::json!(["synthetic-project"])
        );
        assert_eq!(adopted["policy"]["scan_approval_threshold"], 10_485_760);
        let name = "query-bigquery/gcp-audit/service-account-json";
        #[cfg(feature = "query-bigquery")]
        assert_eq!(settings.credential_names(), [name]);
        let key = storage_credential_name(name);
        assert_eq!(key.len(), 63);
        assert!(
            key.bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        );
        assert_ne!(
            key,
            storage_credential_name("query-bigquery/another-source/service-account-json")
        );
        assert_eq!(
            storage_credential_name("AWS_SESSION_TOKEN"),
            "AWS_SESSION_TOKEN"
        );
        Ok(())
    }
}
