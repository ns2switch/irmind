//! The release pins data-only packages; every candidate uses the shared compiler.
type Method = (&'static [u8], &'static str, &'static [u8]);

macro_rules! method {
    ($name:literal, $reference:literal) => {
        (
            include_bytes!(concat!("../../../../../skills/", $name, "/SKILL.md")).as_slice(),
            concat!("references/", $reference),
            include_bytes!(concat!(
                "../../../../../skills/",
                $name,
                "/references/",
                $reference
            ))
            .as_slice(),
        )
    };
}

pub(super) const METHODS: &[Method] = &[
    method!("aws-credential-compromise", "operations.csv"),
    method!("aws-s3-data-exfiltration", "coverage.csv"),
    method!("azure-entra-identity-compromise", "coverage.csv"),
    method!("gcp-service-account-abuse", "coverage.csv"),
    method!("k8s-cluster-compromise", "coverage.csv"),
    method!("k8s-workload-compromise", "coverage.csv"),
    method!("linux-persistence", "coverage.csv"),
    method!("linux-triage", "coverage.csv"),
    method!("linux-webshell", "coverage.csv"),
    method!("malware-execution-triage", "coverage.csv"),
    method!("network-c2-beaconing", "coverage.csv"),
    method!("windows-lateral-movement", "coverage.csv"),
    method!("windows-persistence", "coverage.csv"),
    method!("windows-ransomware", "coverage.csv"),
    method!("windows-triage", "event-ids.csv"),
];
