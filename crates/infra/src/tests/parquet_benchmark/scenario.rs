use super::representative_records;

pub(super) struct Scenario {
    pub(super) precise: bool,
    pub(super) hosts: Option<usize>,
    pub(super) source_bytes: usize,
    pub(super) chronological: bool,
}

impl Scenario {
    pub(super) fn from_environment() -> Self {
        let name = std::env::var("IRMIND_BENCH_SCENARIO").unwrap_or_else(|_| "cloud-v1".into());
        Self::named(&name)
    }

    fn named(name: &str) -> Self {
        let parts = name.split('-').collect::<Vec<_>>();
        assert!(matches!(parts[0], "cloud" | "endpoint"));
        assert!(matches!(parts.get(1), Some(&"v1" | &"v2")));
        let hosts = (parts[0] == "endpoint").then(|| parts[2].parse::<usize>().unwrap());
        assert!(hosts.is_none_or(|n| [1, 64, 1024, 1025].contains(&n)));
        let chronological = parts.last() == Some(&"chronological");
        assert_eq!(
            parts.len(),
            if hosts.is_some() {
                3 + usize::from(chronological)
            } else {
                2
            }
        );
        Self {
            precise: parts[1] == "v2",
            hosts,
            source_bytes: 1_045_000,
            chronological,
        }
    }

    pub(super) fn ingestion_limit(&self, size: &str) -> std::time::Duration {
        std::time::Duration::from_secs(
            if size == "15gb" && self.hosts.is_some() && !self.chronological {
                1350
            } else {
                900
            },
        )
    }

    pub(super) fn ingestion_gate_required(&self, size: &str, mapped: bool) -> bool {
        !(mapped && size == "15gb" && self.hosts == Some(1025) && !self.chronological)
    }

    pub(super) fn name(&self) -> String {
        let version = if self.precise { 2 } else { 1 };
        let mut name = self.hosts.map_or_else(
            || format!("cloud-v{version}"),
            |n| format!("endpoint-v{version}-{n}"),
        );
        if self.chronological {
            name.push_str("-chronological");
        }
        name
    }

    pub(super) fn source(&self, file: usize, multiplier: usize) -> String {
        if let Some(hosts) = self.hosts {
            let mut lines = String::new();
            let mut record = 0;
            while lines.len() < self.source_bytes * if self.chronological { multiplier } else { 1 }
            {
                let sequence = file * 1000 + record;
                // One endpoint per file; the 24/25 additional hosts share the
                // first 24/25 files so every 1,024/1,025-host corpus is complete.
                let host = if hosts > 1000 && file < hosts - 1000 && record % 2 == 1 {
                    file + 1000
                } else {
                    file % hosts
                };
                let row = serde_json::json!({
                    "__REALTIME_TIMESTAMP": (1_793_102_400_000_000u64 + sequence as u64).to_string(),
                    "_HOSTNAME": format!("endpoint-{:04}", host),
                    "_UID": "1000", "_PID": "1234", "_EXE": "/usr/bin/synthetic-client",
                    "_CMDLINE": "synthetic-client --connect 198.18.254.42",
                    "SYSLOG_IDENTIFIER": "synthetic-benchmark",
                    "MESSAGE": format!("needle-{sequence:06} connect dst=198.18.254.42:443 outcome=success {}", "synthetic ".repeat(90)),
                });
                lines.push_str(&row.to_string());
                lines.push('\n');
                record += 1;
            }
            return if self.chronological {
                lines
            } else {
                lines.repeat(multiplier)
            };
        }
        let records = representative_records(file);
        let body = std::iter::repeat_n(records.as_str(), multiplier)
            .collect::<Vec<_>>()
            .join(",");
        format!("{{\"Records\":[{body}]}}")
    }

    pub(super) fn target(&self) -> (&str, &str, &str, &str) {
        if self.hosts.is_some() {
            ("host", "endpoint-0000", "user", "1000")
        } else {
            ("ip", "198.18.254.42", "account", "999900001111")
        }
    }

    pub(super) fn term(&self, scope: &str) -> String {
        if self.hosts.is_none() {
            return "synthetic-000001".into();
        }
        let host = scope
            .strip_prefix("endpoint-")
            .map_or(0, |s| s.parse::<usize>().unwrap());
        let sequence = if host >= 1000 {
            (host - 1000) * 1000 + 1
        } else {
            host * 1000
        };
        format!("needle-{sequence:06}")
    }
}

#[test]
fn endpoint_corpora_have_their_declared_number_of_hosts() {
    for hosts in [1, 64, 1024, 1025] {
        let scenario = Scenario {
            source_bytes: 2048,
            ..Scenario::named(&format!("endpoint-v2-{hosts}"))
        };
        let mut seen = std::collections::BTreeSet::new();
        for file in 0..1000 {
            for line in scenario.source(file, 1).lines() {
                let value: serde_json::Value = serde_json::from_str(line).unwrap();
                seen.insert(value["_HOSTNAME"].as_str().unwrap().to_owned());
            }
        }
        assert_eq!(seen.len(), hosts);
    }
}

#[test]
fn chronological_endpoint_sources_do_not_reset_their_timestamps() {
    for chronological in [false, true] {
        let scenario = Scenario {
            chronological,
            source_bytes: 2048,
            ..Scenario::named("endpoint-v2-64")
        };
        let text = scenario.source(0, 15);
        let times = text
            .lines()
            .map(|line| {
                let v: serde_json::Value = serde_json::from_str(line).unwrap();
                v["__REALTIME_TIMESTAMP"]
                    .as_str()
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(times.windows(2).all(|w| w[0] <= w[1]), chronological);
        assert!(text.len() >= 2048 * 15);
    }
}

#[test]
fn release_and_stress_ingestion_gates_keep_distinct_approved_limits() {
    for version in ["v1", "v2"] {
        assert_eq!(
            Scenario::named(&format!("cloud-{version}"))
                .ingestion_limit("15gb")
                .as_secs(),
            900
        );
        for hosts in [1, 64, 1024, 1025] {
            let base = format!("endpoint-{version}-{hosts}");
            assert_eq!(
                Scenario::named(&base).ingestion_limit("15gb").as_secs(),
                1350
            );
            assert_eq!(Scenario::named(&base).ingestion_limit("1gb").as_secs(), 900);
            assert_eq!(
                Scenario::named(&format!("{base}-chronological"))
                    .ingestion_limit("15gb")
                    .as_secs(),
                900
            );
        }
    }
}

#[cfg(test)]
mod absolute_gate_tests {
    use super::Scenario;
    #[test]
    fn only_the_approved_mapped_1025_host_stress_case_is_nonblocking() {
        for hosts in [1, 64, 1024, 1025] {
            for chronological in [false, true] {
                let scenario = Scenario {
                    precise: true,
                    hosts: Some(hosts),
                    source_bytes: 1024,
                    chronological,
                };
                assert!(scenario.ingestion_gate_required("15gb", false));
                assert!(scenario.ingestion_gate_required("1gib", true));
                assert_eq!(
                    scenario.ingestion_gate_required("15gb", true),
                    hosts != 1025 || chronological
                );
            }
        }
        let cloud = Scenario {
            precise: true,
            hosts: None,
            source_bytes: 1024,
            chronological: false,
        };
        assert!(cloud.ingestion_gate_required("15gb", true));
    }
}
