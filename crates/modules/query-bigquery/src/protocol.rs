use super::{
    AppError, BigQuery, CancelObservationV1, CancellationToken, CompiledSourceQueryV1,
    ExecutionObservationV1, QueryAccounting, QueryExecutionStatus, QueryResponsePage,
    SourceQueryError, SourceQueryUsage, json,
};
use secrecy::ExposeSecret as _;
use serde_json::Value;

const MEBIBYTE: u64 = 1 << 20;
pub(super) const MINIMUM_BILLED_BYTES: u64 = 10 * MEBIBYTE;

pub(super) struct DryRun {
    pub(super) billed_bytes: u64,
    pub(super) reliable: bool,
}

const META_LIMIT: usize = 256 * 1024;
pub(super) const PAGE_LIMIT: usize = 8 * 1024 * 1024;

pub(super) fn job_id(key: &str) -> Result<String, SourceQueryError> {
    if key.len() != 64
        || !key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(SourceQueryError::Invalid);
    }
    Ok(format!("irmind_{key}"))
}

impl BigQuery {
    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        parameters: &[(&str, &str)],
        data: Option<&Value>,
        cancel: &CancellationToken,
    ) -> Result<reqwest::Response, AppError> {
        let url = self
            .endpoint
            .join(path)
            .map_err(|_| SourceQueryError::Invalid)?;
        let mut request = self
            .client
            .request(method, url)
            .query(parameters)
            .bearer_auth(self.token.expose_secret());
        if let Some(data) = data {
            request = request
                .header("content-type", "application/json")
                .body(serde_json::to_vec(data).map_err(|_| AppError::RemoteTool)?);
        }
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(AppError::Cancelled),
            response = request.send() => response.map_err(|_| AppError::RemoteTool),
        }
    }

    pub(super) fn statement(&self, compiled: &CompiledSourceQueryV1) -> Result<Value, AppError> {
        let parameters = compiled.bindings().iter().map(|binding| {
            let kind = match binding.kind.as_str() {
                "text" => "STRING", "timestamp" => "TIMESTAMP", _ => return Err(SourceQueryError::Unsupported),
            };
            let value = binding.value.as_str().ok_or(SourceQueryError::Invalid)?;
            Ok(json!({"name":binding.name,"parameterType":{"type":kind},"parameterValue":{"value":value}}))
        }).collect::<Result<Vec<_>, SourceQueryError>>()?;
        let cap = self.limits.scan_bytes.ok_or(SourceQueryError::Budget)?;
        Ok(
            json!({"query":compiled.text(),"useLegacySql":false,"parameterMode":"NAMED",
            "queryParameters":parameters,"maximumBytesBilled":cap.to_string(),"useQueryCache":false}),
        )
    }

    fn jobs(&self) -> String {
        format!("projects/{}/jobs", self.source.owner())
    }

    pub(super) async fn dry_run(
        &self,
        compiled: &CompiledSourceQueryV1,
        cancel: &CancellationToken,
    ) -> Result<DryRun, AppError> {
        let wire = json!({"jobReference":{"projectId":self.source.owner(),"location":self.source.location()},
            "configuration":{"dryRun":true,"query":self.statement(compiled)?}});
        let response = self
            .send(
                reqwest::Method::POST,
                &self.jobs(),
                &[],
                Some(&wire),
                cancel,
            )
            .await?;
        let result = json_response(response, cancel).await?;
        if !result["status"]["errorResult"].is_null() || result["configuration"]["dryRun"] != true {
            return Err(AppError::RemoteTool);
        }
        let stats = &result["statistics"];
        let query_stats = &stats["query"];
        let processed = count(&query_stats["totalBytesProcessed"])
            .or_else(|| count(&stats["totalBytesProcessed"]))
            .ok_or(SourceQueryError::Unresolved)?;
        let reported = count(&query_stats["totalBytesBilled"]).filter(|bytes| *bytes != 0);
        let minimum_estimate = processed
            .div_ceil(MEBIBYTE)
            .checked_mul(MEBIBYTE)
            .ok_or(SourceQueryError::Budget)?
            .max(MINIMUM_BILLED_BYTES);
        let billed_bytes = reported.unwrap_or(minimum_estimate);
        if billed_bytes < MINIMUM_BILLED_BYTES || Some(billed_bytes) > self.limits.scan_bytes {
            return Err(SourceQueryError::Budget.into());
        }
        // A wildcard can touch multiple tables, each with its own billing floor.
        // Preview estimates never reduce the hold or the provider ceiling.
        let reliable = reported.is_some()
            && matches!(
                query_stats["totalBytesProcessedAccuracy"].as_str(),
                Some("PRECISE" | "UPPER_BOUND")
            );
        Ok(DryRun {
            billed_bytes,
            reliable,
        })
    }

    pub(super) async fn insert(
        &self,
        compiled: &CompiledSourceQueryV1,
        id: &str,
        cancel: &CancellationToken,
    ) -> Result<bool, AppError> {
        let body = json!({"jobReference":{"projectId":self.source.owner(),"location":self.source.location(),"jobId":id},
            "configuration":{"query":self.statement(compiled)?}});
        let response = self
            .send(
                reqwest::Method::POST,
                &self.jobs(),
                &[],
                Some(&body),
                cancel,
            )
            .await?;
        if response.status() == reqwest::StatusCode::CONFLICT {
            return Ok(false);
        }
        let result = json_response(response, cancel).await?;
        self.check_reference(&result, id)?;
        Ok(true)
    }

    pub(super) async fn observe(
        &self,
        compiled: &CompiledSourceQueryV1,
        id: &str,
        cancel: &CancellationToken,
    ) -> Result<ExecutionObservationV1, AppError> {
        let path = format!("{}/{id}", self.jobs());
        let response = self
            .send(
                reqwest::Method::GET,
                &path,
                &[("location", self.source.location())],
                None,
                cancel,
            )
            .await?;
        let result = json_response(response, cancel).await?;
        self.check_reference(&result, id)?;
        let statement = self.statement(compiled)?;
        if statement.as_object().is_none_or(|fields| {
            fields
                .iter()
                .any(|(key, value)| result["configuration"]["query"][key] != *value)
        }) {
            return Err(SourceQueryError::Scope.into());
        }
        let state = &result["status"];
        let status = match state["state"].as_str() {
            Some("PENDING" | "RUNNING") => QueryExecutionStatus::Running,
            Some("DONE") if state["errorResult"]["reason"] == "stopped" => {
                QueryExecutionStatus::Cancelled
            }
            Some("DONE") if !state["errorResult"].is_null() => QueryExecutionStatus::Failed,
            Some("DONE")
                if state["errors"]
                    .as_array()
                    .is_some_and(|list| !list.is_empty()) =>
            {
                QueryExecutionStatus::Partial
            }
            Some("DONE") => QueryExecutionStatus::Succeeded,
            _ => QueryExecutionStatus::Unknown,
        };
        let statistics = &result["statistics"]["query"];
        Ok(ExecutionObservationV1 {
            status,
            request_id: None,
            usage: SourceQueryUsage {
                scanned_bytes: count(&statistics["totalBytesProcessed"]),
                processed_bytes: count(&statistics["totalBytesProcessed"]),
                billed_bytes: count(&statistics["totalBytesBilled"]),
                returned_wire_bytes: 0,
                returned_decoded_bytes: 0,
                query_price_basis: QueryAccounting::ScanPriced,
            },
            source_observation: Some(json!({"job_id":id,"location":self.source.location()})),
        })
    }

    fn check_reference(&self, result: &Value, id: &str) -> Result<(), AppError> {
        let reference = &result["jobReference"];
        if reference["jobId"] != id
            || reference["projectId"] != self.source.owner()
            || reference["location"] != self.source.location()
        {
            return Err(SourceQueryError::Scope.into());
        }
        Ok(())
    }

    pub(super) async fn page(
        &self,
        id: &str,
        token: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<QueryResponsePage, AppError> {
        let path = format!("projects/{}/queries/{id}", self.source.owner());
        let mut params = vec![
            ("location", self.source.location()),
            ("maxResults", "1000"),
            ("formatOptions.useInt64Timestamp", "true"),
            ("timeoutMs", "1000"),
        ];
        if let Some(token) = token {
            if token.is_empty() || token.len() > 4096 {
                return Err(SourceQueryError::Invalid.into());
            }
            params.push(("pageToken", token));
        }
        let response = self
            .send(reqwest::Method::GET, &path, &params, None, cancel)
            .await?;
        let body = response_bytes(response, PAGE_LIMIT, cancel).await?;
        let result: Value = serde_json::from_slice(&body).map_err(|_| AppError::RemoteTool)?;
        self.check_reference(&result, id)?;
        if result["rows"]
            .as_array()
            .is_some_and(|rows| rows.len() > 1_000)
        {
            return Err(SourceQueryError::Limit.into());
        }
        let next_token = result
            .get("pageToken")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty() && token.len() <= 4096)
            .map(str::to_owned);
        let chunks = Box::pin(futures_util::stream::iter(
            (0..body.len())
                .step_by(64 * 1024)
                .map(move |offset| Ok(body[offset..(offset + 64 * 1024).min(body.len())].to_vec())),
        ));
        Ok(QueryResponsePage {
            request_id: None,
            next_token,
            content_encoding: "identity".into(),
            chunks,
        })
    }

    pub(super) async fn stop(
        &self,
        id: &str,
        cancel: &CancellationToken,
    ) -> Result<CancelObservationV1, AppError> {
        let path = format!("{}/{id}/cancel", self.jobs());
        let response = self
            .send(
                reqwest::Method::POST,
                &path,
                &[("location", self.source.location())],
                None,
                cancel,
            )
            .await?;
        let result = json_response(response, cancel).await?;
        self.check_reference(&result["job"], id)?;
        Ok(CancelObservationV1::Requested)
    }
}

async fn json_response(
    response: reqwest::Response,
    cancel: &CancellationToken,
) -> Result<Value, AppError> {
    let bytes = response_bytes(response, META_LIMIT, cancel).await?;
    serde_json::from_slice(&bytes).map_err(|_| AppError::RemoteTool)
}

async fn response_bytes(
    response: reqwest::Response,
    limit: usize,
    cancel: &CancellationToken,
) -> Result<Vec<u8>, AppError> {
    if !response.status().is_success() {
        return Err(AppError::RemoteTool);
    }
    irmind_http::read_limited(response, limit, cancel)
        .await
        .map_err(|error| match error {
            irmind_http::BodyError::Cancelled => AppError::Cancelled,
            _ => AppError::RemoteTool,
        })
}

fn count(value: &Value) -> Option<u64> {
    value.as_str().and_then(|value| value.parse().ok())
}
