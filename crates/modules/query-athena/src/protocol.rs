use crate::Athena;
use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings, sign};
use irmind_app::{
    AppError, CancellationToken, ObjectStream,
    source_queries::{
        CancelObservationV1, CompiledSourceQueryV1, ExecutionObservationV1, QueryAccounting,
        QueryExecutionStatus, QueryResponsePage, SourceQueryError, SourceQueryUsage,
    },
};
use serde_json::{Value, json};

const MEBIBYTE: u64 = 1 << 20;
pub(super) const MINIMUM_BILLED_BYTES: u64 = 10 * MEBIBYTE;

pub(super) fn billable_bytes(scanned: u64) -> Option<u64> {
    scanned
        .div_ceil(MEBIBYTE)
        .checked_mul(MEBIBYTE)
        .map(|rounded| rounded.max(MINIMUM_BILLED_BYTES))
}

pub(super) const METADATA_LIMIT: usize = 256 * 1024;
pub(super) const PAGE_LIMIT: usize = 8 * 1024 * 1024;

impl Athena {
    pub(super) async fn post(
        &self,
        action: &str,
        value: &Value,
        max: usize,
        cancel: &CancellationToken,
    ) -> Result<Value, AppError> {
        let bytes = self.wire(action, value, max, cancel).await?;
        serde_json::from_slice(&bytes).map_err(|_| AppError::RemoteTool)
    }

    async fn wire(
        &self,
        action: &str,
        value: &Value,
        max: usize,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        let mut request = http::Request::post(self.endpoint.as_str())
            .header("content-type", "application/x-amz-json-1.1")
            .header("x-amz-target", format!("AmazonAthena.{action}"))
            .body(serde_json::to_vec(value).map_err(|_| AppError::RemoteTool)?)
            .map_err(|_| AppError::RemoteTool)?;
        let identity = self.credentials.clone().into();
        let params = aws_sigv4::sign::v4::SigningParams::builder()
            .identity(&identity)
            .region(self.source.location())
            .name("athena")
            .time(std::time::SystemTime::now())
            .settings(SigningSettings::default())
            .build()
            .map_err(|_| AppError::RemoteTool)?;
        let headers = request
            .headers()
            .iter()
            .map(|(name, value)| {
                value
                    .to_str()
                    .map(|value| (name.as_str(), value))
                    .map_err(|_| AppError::RemoteTool)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let signable = SignableRequest::new(
            "POST",
            self.endpoint.as_str(),
            headers.into_iter(),
            SignableBody::Bytes(request.body()),
        )
        .map_err(|_| AppError::RemoteTool)?;
        let (signature, _) = sign(signable, &params.into())
            .map_err(|_| AppError::RemoteTool)?
            .into_parts();
        signature.apply_to_request_http1x(&mut request);
        let (parts, body) = request.into_parts();
        let response = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(AppError::Cancelled),
            response = self.client.post(self.endpoint.clone()).headers(parts.headers).body(body).send() =>
                response.map_err(|_| AppError::RemoteTool)?,
        };
        if !response.status().is_success() {
            return Err(AppError::RemoteTool);
        }
        irmind_http::read_limited(response, max, cancel)
            .await
            .map_err(|error| match error {
                irmind_http::BodyError::Cancelled => AppError::Cancelled,
                _ => AppError::RemoteTool,
            })
    }

    pub(super) async fn start(
        &self,
        query: &CompiledSourceQueryV1,
        token: &str,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(SourceQueryError::Invalid.into());
        }
        let database = self
            .source
            .table()
            .split_once('.')
            .ok_or(SourceQueryError::Invalid)?
            .0;
        let bindings = query
            .bindings()
            .iter()
            .map(|binding| {
                let val = binding.value.as_str().ok_or(SourceQueryError::Invalid)?;
                // Athena receives its parameter literals separately from SQL.
                Ok(format!("'{}'", val.replace('\'', "''")))
            })
            .collect::<Result<Vec<_>, SourceQueryError>>()?;
        let result = self
            .post(
                "StartQueryExecution",
                &json!({
                    "ClientRequestToken": token,
                    "ExecutionParameters": bindings,
                    "QueryExecutionContext": {"Catalog": "AwsDataCatalog", "Database": database},
                    "QueryString": query.text(),
                    "WorkGroup": self.workgroup,
                    "ResultReuseConfiguration": {"ResultReuseByAgeConfiguration":{"Enabled":false}}
                }),
                METADATA_LIMIT,
                cancel,
            )
            .await?;
        let id = result["QueryExecutionId"]
            .as_str()
            .ok_or(AppError::RemoteTool)?;
        check_job_id(id)?;
        Ok(id.into())
    }

    pub(super) async fn observe(
        &self,
        job: &str,
        cancel: &CancellationToken,
    ) -> Result<ExecutionObservationV1, AppError> {
        check_job_id(job)?;
        let response = self
            .post(
                "GetQueryExecution",
                &json!({"QueryExecutionId":job}),
                METADATA_LIMIT,
                cancel,
            )
            .await?;
        let info = &response["QueryExecution"];
        if info["QueryExecutionId"] != job || info["WorkGroup"] != self.workgroup {
            return Err(SourceQueryError::Scope.into());
        }
        let statistics = &info["Statistics"];
        let status = match info["Status"]["State"].as_str() {
            Some("QUEUED" | "RUNNING") => QueryExecutionStatus::Running,
            Some("SUCCEEDED") => QueryExecutionStatus::Succeeded,
            Some("FAILED") => QueryExecutionStatus::Failed,
            Some("CANCELLED") => QueryExecutionStatus::Cancelled,
            _ => QueryExecutionStatus::Unknown,
        };
        let scanned_bytes = statistics["DataScannedInBytes"].as_u64();
        let billed_bytes = match status {
            QueryExecutionStatus::Succeeded | QueryExecutionStatus::Cancelled => {
                scanned_bytes.and_then(billable_bytes)
            }
            QueryExecutionStatus::Failed => Some(0),
            _ => None,
        };
        Ok(ExecutionObservationV1 {
            status,
            request_id: None,
            usage: SourceQueryUsage {
                scanned_bytes,
                processed_bytes: None,
                billed_bytes,
                returned_wire_bytes: 0,
                returned_decoded_bytes: 0,
                query_price_basis: QueryAccounting::ScanPriced,
            },
            source_observation: Some(json!({"job_id": job, "workgroup":self.workgroup})),
        })
    }

    pub(super) async fn fetch_page(
        &self,
        job: &str,
        token: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<QueryResponsePage, AppError> {
        check_job_id(job)?;
        let mut body = json!({"QueryExecutionId":job,"MaxResults":1000});
        if let Some(token) = token {
            if token.is_empty() || token.len() > 4096 {
                return Err(SourceQueryError::Invalid.into());
            }
            body["NextToken"] = json!(token);
        }
        let bytes = self
            .wire("GetQueryResults", &body, PAGE_LIMIT, cancel)
            .await?;
        let page: Value = serde_json::from_slice(&bytes).map_err(|_| AppError::RemoteTool)?;
        if page["ResultSet"]["Rows"]
            .as_array()
            .is_none_or(|rows| rows.len() > 1000)
        {
            return Err(SourceQueryError::Limit.into());
        }
        let next_token = match page.get("NextToken") {
            None => None,
            Some(token) => Some(
                token
                    .as_str()
                    .filter(|t| !t.is_empty() && t.len() <= 4096)
                    .ok_or(SourceQueryError::Invalid)?
                    .into(),
            ),
        };
        let chunks: ObjectStream = Box::pin(futures_util::stream::iter(
            (0..bytes.len()).step_by(64 * 1024).map(move |offset| {
                Ok(bytes[offset..(offset + 64 * 1024).min(bytes.len())].to_vec())
            }),
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
        job: &str,
        cancel: &CancellationToken,
    ) -> Result<CancelObservationV1, AppError> {
        check_job_id(job)?;
        let response = self
            .post(
                "StopQueryExecution",
                &json!({"QueryExecutionId":job}),
                METADATA_LIMIT,
                cancel,
            )
            .await;
        match response {
            Ok(_) => Ok(CancelObservationV1::Requested),
            Err(AppError::Cancelled) => Err(AppError::Cancelled),
            Err(_) => Ok(CancelObservationV1::Unknown),
        }
    }
}

fn check_job_id(id: &str) -> Result<(), SourceQueryError> {
    if id.len() != 36
        || !id.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return Err(SourceQueryError::Invalid);
    }
    Ok(())
}
