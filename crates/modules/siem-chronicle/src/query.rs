use super::{AppError, Chronicle, invalid_query};
use irmind_domain::{AuthorizedCall, SiemAggregation, SiemField, SiemOperator, SiemQuery};
fn field(field: SiemField) -> &'static str {
    match field {
        SiemField::EventName => "metadata.product_event_type",
        SiemField::User => "principal.user.userid",
        SiemField::SourceIp => "principal.ip",
        SiemField::Host => "principal.hostname",
    }
}
fn literal(value: &str) -> Result<String, AppError> {
    serde_json::to_string(value).map_err(|_| invalid_query())
}
fn prefix(value: &str) -> String {
    let mut escaped = String::from("/^");
    for c in value.chars() {
        if ".[](){}^$|*+?\\/".contains(c) {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped.push('/');
    escaped
}
impl Chronicle {
    pub(super) fn search_url(&self, call: &AuthorizedCall) -> Result<reqwest::Url, AppError> {
        let query = SiemQuery::parse(call.proposal_args()).ok_or_else(invalid_query)?;
        let account = call.arg("account").ok_or_else(invalid_query)?;
        let predicate = match query.operator() {
            SiemOperator::Equals => {
                format!("{} = {}", field(query.field()), literal(query.value())?)
            }
            SiemOperator::NotEquals => format!(
                "{field} != \"\" AND {field} != {value}",
                field = field(query.field()),
                value = literal(query.value())?
            ),
            SiemOperator::Prefix => format!("{} = {}", field(query.field()), prefix(query.value())),
        };
        let mut text = if self.scope_mode == irmind_app::SiemScopeMode::EventAccount {
            format!(
                "{} = {} AND ({predicate})",
                self.account_field,
                literal(account)?
            )
        } else {
            self.check_scope(call)?;
            format!("({predicate})")
        };
        append_aggregation(&mut text, &query)?;
        let mut url = self
            .endpoint
            .join(&format!("v1alpha/{}:udmSearch", self.resource))
            .map_err(|_| invalid_query())?;
        url.query_pairs_mut().extend_pairs([
            ("query", text.as_str()),
            ("timeRange.startTime", query.from().as_str()),
            ("timeRange.endTime", query.to().as_str()),
            ("queryDialect", "YL2"),
            ("limit", query.limit().to_string().as_str()),
        ]);
        Ok(url)
    }
}
fn append_aggregation(text: &mut String, query: &SiemQuery) -> Result<(), AppError> {
    use std::fmt::Write as _;
    if query.aggregation() == SiemAggregation::Events {
        return Ok(());
    }
    let group = field(query.group_by().ok_or_else(invalid_query)?);
    write!(text, "\nmatch:\n  {group}").map_err(|_| invalid_query())?;
    if query.aggregation() == SiemAggregation::Distinct {
        write!(text, "\norder:\n  {group} asc").map_err(|_| invalid_query())?;
    } else {
        text.push_str("\noutcome:\n  $count = count(metadata.id)\norder:\n  $count desc");
    }
    write!(text, "\nlimit:\n  {}", query.limit()).map_err(|_| invalid_query())
}
