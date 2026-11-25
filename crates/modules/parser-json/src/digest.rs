use serde::{Deserialize, de::IgnoredAny};
use std::io::Read as _;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DigestSample {
    digest_start_time: String,
    digest_end_time: String,
    digest_s3_bucket: String,
    digest_s3_object: String,
    digest_public_key_fingerprint: String,
    digest_signature_algorithm: String,
    log_files: Option<Vec<IgnoredAny>>,
    #[serde(rename = "Records")]
    records: Option<IgnoredAny>,
}

impl DigestSample {
    fn has_integrity_header(&self) -> bool {
        self.records.is_none()
            && !self.digest_start_time.is_empty()
            && !self.digest_end_time.is_empty()
            && !self.digest_s3_bucket.is_empty()
            && is_digest_key(&self.digest_s3_object)
            && self.digest_signature_algorithm == "SHA256withRSA"
            && self.digest_public_key_fingerprint.len() == 32
            && self
                .digest_public_key_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
    }
}

fn is_digest_key(key: &str) -> bool {
    key.split('/').any(|part| part == "CloudTrail-Digest")
        || leaf(key).contains("_CloudTrail-Digest_")
}

fn leaf(key: &str) -> &str {
    key.rsplit('/').next().unwrap_or(key)
}

pub(super) fn detect(source: &str, sample: &[u8], clipped: bool) -> bool {
    match serde_json::from_slice::<DigestSample>(sample) {
        Ok(digest) => digest.has_integrity_header() && digest.log_files.is_some(),
        Err(error) if clipped && error.is_eof() && is_digest_key(source) => {
            // The standard AWS document places the logFiles array after its
            // header. A large array may not fit in the probe. Require the exact
            // digest filename and a complete typed header before the array.
            const LOG_FILES: &[u8] = b"\"logFiles\"";
            let Some(at) = sample
                .windows(LOG_FILES.len())
                .position(|window| window == LOG_FILES)
            else {
                return false;
            };
            let Some(after_key) = sample[at + LOG_FILES.len()..]
                .trim_ascii_start()
                .strip_prefix(b":")
            else {
                return false;
            };
            if !after_key.trim_ascii_start().starts_with(b"[") {
                return false;
            }
            let Some(header) = sample[..at].trim_ascii_end().strip_suffix(b",") else {
                return false;
            };
            serde_json::from_reader::<_, DigestSample>(header.chain(&b"}"[..])).is_ok_and(
                |digest| {
                    digest.has_integrity_header() && leaf(&digest.digest_s3_object) == leaf(source)
                },
            )
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AWSLogs/111122223333/CloudTrail-Digest/us-east-2/2026/11/01/111122223333_CloudTrail-Digest_us-east-2_synthetic_us-east-2_20261101T010000Z.json.gz";

    fn header() -> String {
        serde_json::json!({
            "digestStartTime": "2026-11-01T00:00:00Z",
            "digestEndTime": "2026-11-01T01:00:00Z",
            "digestS3Bucket": "synthetic",
            "digestS3Object": KEY,
            "digestPublicKeyFingerprint": "00000000000000000000000000000000",
            "digestSignatureAlgorithm": "SHA256withRSA"
        })
        .to_string()
    }

    #[test]
    fn typed_digest_detection_does_not_discard_logs_by_filename() {
        let header = header();
        let prefix = header.trim_end_matches('}');
        let digest = format!("{prefix},\"logFiles\":[]}}");
        assert!(detect("download", digest.as_bytes(), false));
        assert!(!detect(
            KEY,
            br#"{"Records":[{"eventName":"ConsoleLogin"}]}"#,
            false
        ));
        let mixed =
            format!("{prefix},\"logFiles\":[],\"Records\":[{{\"eventName\":\"ConsoleLogin\"}}]}}");
        assert!(!detect(KEY, mixed.as_bytes(), false));
        let large = format!(
            "{prefix},\"logFiles\":[{}",
            " ".repeat(super::super::gzip::SAMPLE_BYTES)
        );
        let sample = &large.as_bytes()[..super::super::gzip::SAMPLE_BYTES];
        assert!(detect(KEY, sample, true));
        assert!(!detect("renamed.json", sample, true));
        assert!(!detect(KEY, sample, false));
    }
}
