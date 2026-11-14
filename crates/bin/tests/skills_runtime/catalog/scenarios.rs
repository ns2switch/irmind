use super::Scenario;

pub(super) const SCENARIOS: &[Scenario] = &[
    Scenario {
        cluster: None,
        name: "aws-s3-data-exfiltration",
        files: &[(
            "cloudtrail.json",
            "parser-json",
            include_str!(
                "../../../../testkit/fixtures/skills-expanded/aws-s3-data-exfiltration/source/cloudtrail.json"
            ),
        )],
        query: "GetObject",
        conclusion: "Successful synthetic S3 read after a policy-change event; transfer volume unproven",
        technique: "T1530",
        selected_source: 0,
        filters: &[
            ("event_category", "api"),
            ("event_type", "access"),
            ("event_outcome", "success"),
            ("entity_role", "source"),
        ],
    },
    Scenario {
        cluster: None,
        name: "azure-entra-identity-compromise",
        files: &[
            (
                "hunteval.json",
                "parser-json",
                include_str!(
                    "../../../../testkit/fixtures/skills-expanded/azure-entra-identity-compromise/source/hunteval.json"
                ),
            ),
            (
                "entra-native.ndjson",
                "parser-entra",
                include_str!(
                    "../../../../testkit/fixtures/parser-entra/source/audit-resource.ndjson"
                ),
            ),
            (
                "entra-signin.ndjson",
                "parser-entra",
                include_str!(
                    "../../../../testkit/fixtures/parser-entra/source/signin-resource.ndjson"
                ),
            ),
        ],
        query: "credential",
        conclusion: "Synthetic application credential added; suspicious sign-in requires separate review",
        technique: "T1098.001",
        selected_source: 1,
        filters: &[
            ("event_category", "iam"),
            ("event_type", "info"),
            ("event_outcome", "success"),
            ("entity_role", "actor"),
        ],
    },
    Scenario {
        cluster: None,
        name: "gcp-service-account-abuse",
        files: &[
            (
                "hunteval.json",
                "parser-json",
                include_str!(
                    "../../../../testkit/fixtures/skills-expanded/gcp-service-account-abuse/source/hunteval.json"
                ),
            ),
            (
                "cloud-audit.json",
                "parser-gcp-audit",
                include_str!(
                    "../../../../testkit/fixtures/skills-expanded/gcp-service-account-abuse/source/cloud-audit.json"
                ),
            ),
        ],
        query: "CreateServiceAccountKey",
        conclusion: "Synthetic service-account key creation recorded; compromise remains a hypothesis",
        technique: "T1098.001",
        selected_source: 1,
        filters: &[
            ("event_category", "iam"),
            ("event_type", "access"),
            ("event_outcome", "success"),
            ("entity_role", "actor"),
        ],
    },
    Scenario {
        cluster: None,
        name: "windows-ransomware",
        files: &[(
            "normalized-ecs.jsonl",
            "parser-ecs",
            include_str!(
                "../../../../testkit/fixtures/skills-expanded/windows-ransomware/source/normalized-ecs.jsonl"
            ),
        )],
        query: "vssadmin",
        conclusion: "Recorded recovery-inhibition command; encryption is not established",
        technique: "T1490",
        selected_source: 0,
        filters: &[
            ("event_category", "process"),
            ("event_type", "start"),
            ("event_outcome", "success"),
            ("entity_role", "actor"),
        ],
    },
    Scenario {
        cluster: None,
        name: "windows-lateral-movement",
        files: &[(
            "normalized-ecs.jsonl",
            "parser-ecs",
            include_str!(
                "../../../../testkit/fixtures/skills-expanded/windows-lateral-movement/source/normalized-ecs.jsonl"
            ),
        )],
        query: "4624",
        conclusion: "Successful synthetic RDP logon; pass-the-hash is not established",
        technique: "T1021.001",
        selected_source: 0,
        filters: &[
            ("event_category", "authentication"),
            ("event_type", "start"),
            ("event_outcome", "success"),
            ("entity_role", "actor"),
        ],
    },
    Scenario {
        cluster: None,
        name: "windows-persistence",
        files: &[(
            "normalized-ecs.jsonl",
            "parser-ecs",
            include_str!(
                "../../../../testkit/fixtures/skills-expanded/windows-persistence/source/normalized-ecs.jsonl"
            ),
        )],
        query: "RunOnce",
        conclusion: "Synthetic RunOnce value configured; execution remains unobserved",
        technique: "T1547.001",
        selected_source: 0,
        filters: &[
            ("event_category", "registry"),
            ("event_type", "change"),
            ("event_outcome", "success"),
            ("entity_role", "actor"),
        ],
    },
    Scenario {
        cluster: None,
        name: "malware-execution-triage",
        files: &[(
            "normalized-ecs.jsonl",
            "parser-ecs",
            include_str!(
                "../../../../testkit/fixtures/skills-expanded/malware-execution-triage/source/normalized-ecs.jsonl"
            ),
        )],
        query: "sample.exe",
        conclusion: "Synthetic sample.exe launched a command shell; maliciousness remains unproven",
        technique: "T1059.003",
        selected_source: 0,
        filters: &[
            ("event_category", "process"),
            ("event_type", "start"),
            ("event_outcome", "success"),
            ("entity_role", "actor"),
        ],
    },
    Scenario {
        cluster: None,
        name: "linux-webshell",
        files: &[
            (
                "access.log",
                "parser-linux",
                include_str!(
                    "../../../../testkit/fixtures/skills-expanded/linux-webshell/source/access.log"
                ),
            ),
            (
                "audit.log",
                "parser-linux",
                include_str!(
                    "../../../../testkit/fixtures/skills-expanded/linux-webshell/source/audit.log"
                ),
            ),
        ],
        query: "GET",
        conclusion: "Synthetic HTTP request near web-uid shell execution; causal webshell link is unproven",
        technique: "T1059.004",
        selected_source: 0,
        filters: &[
            ("event_category", "web"),
            ("event_type", "access"),
            ("event_outcome", "success"),
            ("entity_role", "source"),
        ],
    },
    Scenario {
        cluster: None,
        name: "linux-persistence",
        files: &[
            (
                "audit.log",
                "parser-linux",
                include_str!(
                    "../../../../testkit/fixtures/skills-expanded/linux-persistence/source/audit.log"
                ),
            ),
            (
                "collected-cron.json",
                "parser-json",
                include_str!(
                    "../../../../testkit/fixtures/skills-expanded/linux-persistence/source/collected-cron.json"
                ),
            ),
        ],
        query: "crontab",
        conclusion: "Collected synthetic cron configuration and crontab execution",
        technique: "T1053.003",
        selected_source: 0,
        filters: &[
            ("event_category", "process"),
            ("event_type", "start"),
            ("event_outcome", "success"),
        ],
    },
    Scenario {
        cluster: None,
        name: "network-c2-beaconing",
        files: &[
            (
                "conn.jsonl",
                "parser-zeek",
                include_str!(
                    "../../../../testkit/fixtures/skills-expanded/network-c2-beaconing/source/conn.jsonl"
                ),
            ),
            (
                "eve.jsonl",
                "parser-suricata",
                include_str!(
                    "../../../../testkit/fixtures/skills-expanded/network-c2-beaconing/source/eve.jsonl"
                ),
            ),
        ],
        query: "203.0.113.77",
        conclusion: "Four synthetic connections at 60-second intervals; C2 remains unconfirmed",
        technique: "T1071.001",
        selected_source: 0,
        filters: &[
            ("event_category", "network"),
            ("event_type", "connection"),
            ("event_outcome", "unknown"),
            ("entity_role", "destination"),
        ],
    },
    #[cfg(all(feature = "parser-kubernetes", feature = "parser-falco"))]
    Scenario {
        cluster: Some("kubernetes:urn:k8s:synthetic"),
        name: "k8s-cluster-compromise",
        files: &[(
            "audit.ndjson",
            "parser-kubernetes",
            include_str!(
                "../../../../testkit/fixtures/skills-expanded/k8s-cluster-compromise/source/audit.ndjson"
            ),
        )],
        query: "secrets",
        conclusion: "Failed synthetic secret read followed by a successful cluster-role binding; effective privileges need separate RBAC state",
        technique: "T1098.006",
        selected_source: 0,
        filters: &[
            ("event_category", "api"),
            ("event_type", "access"),
            ("event_outcome", "failure"),
            ("entity_role", "actor"),
        ],
    },
    #[cfg(all(feature = "parser-kubernetes", feature = "parser-falco"))]
    Scenario {
        cluster: Some("kubernetes:urn:k8s:synthetic"),
        name: "k8s-workload-compromise",
        files: &[
            (
                "audit.ndjson",
                "parser-kubernetes",
                include_str!(
                    "../../../../testkit/fixtures/skills-expanded/k8s-workload-compromise/source/audit.ndjson"
                ),
            ),
            (
                "falco.ndjson",
                "parser-falco",
                include_str!(
                    "../../../../testkit/fixtures/skills-expanded/k8s-workload-compromise/source/falco.ndjson"
                ),
            ),
        ],
        query: "pods",
        conclusion: "Successful synthetic risky pod creation correlates with a Falco source alert; node escape is not established",
        technique: "T1610",
        selected_source: 0,
        filters: &[
            ("event_category", "api"),
            ("event_type", "access"),
            ("event_outcome", "success"),
            ("entity_role", "actor"),
        ],
    },
];
