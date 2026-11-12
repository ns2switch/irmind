//! Documented legacySearchDetections: server window and explicit instance namespace.
use super::{AppError, CancellationToken, Chronicle, invalid_query};
use irmind_domain::{AuthorizedCall, IndexedTime, UtcTimestamp};
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use std::collections::BTreeSet;
const MAX_BYTES: usize = 5_000_000;
const MAX_DETECTIONS: usize = 20;
const MAX_PAGES: usize = 4;
struct Page {
    detections: Vec<Value>,
    next: String,
    partial: bool,
}
impl Page {
    fn parse(raw: &[u8]) -> Result<Self, AppError> {
        irmind_app::source_mapping::json::validate_json_value(
            raw,
            irmind_app::source_mapping::json::SourceJsonLimits::default(),
        )
        .map_err(|_| AppError::RemoteTool)?;
        let mut body: Value = serde_json::from_slice(raw).map_err(|_| AppError::RemoteTool)?;
        if !body.is_object() || body.get("nestedDetectionSamples").is_some() {
            return Err(AppError::RemoteTool);
        }
        let detections = match body.get_mut("detections") {
            Some(Value::Array(values)) if values.len() <= MAX_DETECTIONS => std::mem::take(values),
            None => Vec::new(),
            _ => return Err(AppError::RemoteTool),
        };
        let next = match body.get("nextPageToken") {
            Some(Value::String(value))
                if value.len() <= 2048 && !value.chars().any(char::is_control) =>
            {
                value.clone()
            }
            None => String::new(),
            _ => return Err(AppError::RemoteTool),
        };
        let partial = match body.get("respTooLargeDetectionsTruncated") {
            Some(Value::Bool(value)) => *value,
            None => false,
            _ => return Err(AppError::RemoteTool),
        };
        Ok(Self {
            detections,
            next,
            partial,
        })
    }
}
impl Chronicle {
    pub(super) async fn detections(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        if self.scope_mode != irmind_app::SiemScopeMode::Instance {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::ChronicleDetectionScopeUnsupported,
            )));
        }
        self.check_scope(call)?;
        let rule = self.rule_id.as_deref().ok_or_else(|| {
            AppError::Policy(
                "Configure IRMIND_CHRONICLE_RULE_ID before reading Chronicle detections".into(),
            )
        })?;
        let id = call
            .arg("alert_id")
            .filter(|v| !v.is_empty() && v.len() <= 256 && !v.chars().any(char::is_control))
            .ok_or_else(invalid_query)?;
        let (from, to) = window(call)?;
        let token = self
            .credentials
            .token(&self.client, &self.token_endpoint, cancel)
            .await?;
        let mut scan = Scan::default();
        for _ in 0..MAX_PAGES {
            let url = self.detection_url(rule, &from, &to, &scan.next)?;
            let raw = self
                .read(url, token.expose_secret(), MAX_BYTES - scan.bytes, cancel)
                .await?;
            scan.bytes += raw.len();
            scan.accept(Page::parse(&raw)?, id, &from, &to)?;
            if scan.found.is_some()
                || scan.next.is_empty()
                || scan.seen >= MAX_DETECTIONS
                || scan.bytes == MAX_BYTES
            {
                break;
            }
        }
        scan.result(id)
    }
    fn detection_url(
        &self,
        rule: &str,
        from: &UtcTimestamp,
        to: &UtcTimestamp,
        page: &str,
    ) -> Result<reqwest::Url, AppError> {
        let mut url = self
            .endpoint
            .join(&format!(
                "v1alpha/{}/legacy:legacySearchDetections",
                self.resource
            ))
            .map_err(|_| invalid_query())?;
        url.query_pairs_mut().extend_pairs([
            ("ruleId", rule),
            ("startTime", from.as_str()),
            ("endTime", to.as_str()),
            ("listBasis", "DETECTION_TIME"),
            ("pageSize", "20"),
            ("maxRespSizeBytes", "5000000"),
            ("includeNestedDetections", "false"),
        ]);
        if !page.is_empty() {
            url.query_pairs_mut().append_pair("pageToken", page);
        }
        Ok(url)
    }
}
#[derive(Default)]
struct Scan {
    bytes: usize,
    seen: usize,
    pages: usize,
    next: String,
    tokens: BTreeSet<String>,
    partial: bool,
    found: Option<Value>,
}
impl Scan {
    fn accept(
        &mut self,
        page: Page,
        id: &str,
        from: &UtcTimestamp,
        to: &UtcTimestamp,
    ) -> Result<(), AppError> {
        self.pages += 1;
        self.partial |= page.partial || self.seen + page.detections.len() > MAX_DETECTIONS;
        self.next = page.next;
        if !self.next.is_empty() && !self.tokens.insert(self.next.clone()) {
            return Err(AppError::RemoteTool);
        }
        for detection in page.detections.into_iter().take(MAX_DETECTIONS - self.seen) {
            self.seen += 1;
            let identity = detection
                .get("id")
                .and_then(Value::as_str)
                .ok_or(AppError::RemoteTool)?;
            let at = detection
                .get("detectionTime")
                .and_then(Value::as_str)
                .ok_or(AppError::RemoteTool)?;
            let at = IndexedTime::from_rfc3339(at, false).map_err(|_| AppError::RemoteTool)?;
            let lower = IndexedTime::from_rfc3339(from.as_str(), false)
                .map_err(|_| AppError::RemoteTool)?;
            let upper =
                IndexedTime::from_rfc3339(to.as_str(), false).map_err(|_| AppError::RemoteTool)?;
            if at.instant() < lower.instant() || at.instant() >= upper.instant() {
                return Err(AppError::RemoteTool);
            }
            if identity == id {
                if self.found.is_some() {
                    return Err(AppError::RemoteTool);
                }
                self.found = Some(detection);
            }
        }
        Ok(())
    }
    fn result(self, id: &str) -> Result<Vec<u8>, AppError> {
        let partial = self.partial || !self.next.is_empty();
        let status = if self.found.is_some() {
            "found"
        } else if partial {
            "partial_not_found"
        } else {
            "not_found"
        };
        let detections = self.found.into_iter().collect::<Vec<_>>();
        let raw = serde_json::to_vec(
            &json!({"detections":detections,"requested_id":id,"partial":partial,"truncated":partial,
            "status":status,"scanned":self.seen,"pages":self.pages,"scope_mode":"instance"}),
        )
        .map_err(|_| AppError::RemoteTool)?;
        let fields = irmind_app::source_mapping::json::decode_json_fields(
            &raw,
            irmind_app::source_mapping::json::SourceJsonLimits::default(),
        )
        .map_err(|_| AppError::RemoteTool)?;
        irmind_app::source_mapping::json::render_source_fields(&fields)
            .map(String::into_bytes)
            .map_err(|_| AppError::RemoteTool)
    }
}
fn window(call: &AuthorizedCall) -> Result<(UtcTimestamp, UtcTimestamp), AppError> {
    let from = UtcTimestamp::parse(call.arg("from").ok_or_else(invalid_query)?)
        .map_err(|_| invalid_query())?;
    let to = UtcTimestamp::parse(call.arg("to").ok_or_else(invalid_query)?)
        .map_err(|_| invalid_query())?;
    if !(1..=86_400).contains(&(to.unix_seconds() - from.unix_seconds())) {
        return Err(invalid_query());
    }
    Ok((from, to))
}
