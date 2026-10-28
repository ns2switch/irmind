use super::{AppError, ModuleConfig, Splunk, safe_alert_id, safe_field, safe_identifier};
use irmind_domain::{SiemAggregation, SiemField, SiemOperator, SiemQuery};

pub(super) struct SearchFields {
    event_name: String,
    user: String,
    source_ip: String,
    host: String,
}

impl SearchFields {
    pub(super) fn from_config(config: &ModuleConfig) -> Self {
        Self {
            event_name: config
                .value("IRMIND_SPLUNK_EVENT_NAME_FIELD")
                .unwrap_or("eventName")
                .to_owned(),
            user: config
                .value("IRMIND_SPLUNK_USER_FIELD")
                .unwrap_or("user")
                .to_owned(),
            source_ip: config
                .value("IRMIND_SPLUNK_SOURCE_IP_FIELD")
                .unwrap_or("sourceIPAddress")
                .to_owned(),
            host: config
                .value("IRMIND_SPLUNK_HOST_FIELD")
                .unwrap_or("host")
                .to_owned(),
        }
    }

    pub(super) fn valid(&self) -> bool {
        [&self.event_name, &self.user, &self.source_ip, &self.host]
            .iter()
            .all(|field| safe_field(field))
    }

    fn field(&self, field: SiemField) -> &str {
        match field {
            SiemField::EventName => &self.event_name,
            SiemField::User => &self.user,
            SiemField::SourceIp => &self.source_ip,
            SiemField::Host => &self.host,
        }
    }
}

impl Splunk {
    pub(super) fn spl_search(&self, account: &str, query: &SiemQuery) -> Result<String, AppError> {
        if !safe_identifier(account) {
            return Err(invalid_structured_query());
        }
        let field = render_spl_field(self.search_fields.field(query.field()));
        let value = escape_spl_value(query.value());
        let comparison = match query.operator() {
            SiemOperator::Equals => format!("{field}=\"{value}\""),
            SiemOperator::NotEquals => format!("{field}!=\"{value}\""),
            SiemOperator::Prefix => format!("{field}=\"{value}*\""),
        };
        let suffix = match query.aggregation() {
            SiemAggregation::Events => format!("head {}", query.limit()),
            SiemAggregation::CountBy => format!(
                "stats count by {} | head {}",
                self.group_field(query)?,
                query.limit()
            ),
            SiemAggregation::Top => {
                format!("top limit={} {}", query.limit(), self.group_field(query)?)
            }
            SiemAggregation::Distinct => {
                let group = self.group_field(query)?;
                format!("dedup {group} | table {group} | head {}", query.limit())
            }
        };
        Ok(format!(
            "search index={} {}=\"{}\" {comparison} | {suffix}",
            self.index,
            render_spl_field(&self.account_field),
            account
        ))
    }

    fn group_field(&self, query: &SiemQuery) -> Result<String, AppError> {
        query
            .group_by()
            .map(|field| render_spl_field(self.search_fields.field(field)))
            .ok_or_else(invalid_structured_query)
    }

    pub(super) fn spl_alert(&self, account: &str, alert_id: &str) -> Result<String, AppError> {
        if !safe_identifier(account) || !safe_alert_id(alert_id) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidSplunkAlertId,
            )));
        }
        Ok(format!(
            "search index={} {}=\"{}\" {}=\"{}\" | head 1",
            self.index,
            render_spl_field(&self.account_field),
            account,
            render_spl_field(&self.alert_id_field),
            alert_id
        ))
    }
}

fn invalid_structured_query() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
        irmind_app::AdapterPolicyError::InvalidStructuredSplunkQuery,
    ))
}

fn escape_spl_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn render_spl_field(field: &str) -> String {
    if field
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        && field
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        field.to_owned()
    } else {
        format!("\"{field}\"")
    }
}
