use super::{AppError, Elastic, invalid_query};
use irmind_domain::{
    AuthorizedCall, SiemAggregation, SiemField, SiemOperator, SiemQuery, Tool, UtcTimestamp,
};
use serde_json::{Value, json};
fn field(value: SiemField) -> &'static str {
    match value {
        SiemField::EventName => "event.action",
        SiemField::User => "user.name",
        SiemField::SourceIp => "source.ip",
        SiemField::Host => "host.name",
    }
}
impl Elastic {
    pub(super) fn query(&self, call: &AuthorizedCall) -> Result<Value, AppError> {
        let get = |key| call.arg(key).ok_or_else(invalid_query);
        let from = UtcTimestamp::parse(get("from")?).map_err(|_| invalid_query())?;
        let to = UtcTimestamp::parse(get("to")?).map_err(|_| invalid_query())?;
        if !(1..=86_400).contains(&(to.unix_seconds() - from.unix_seconds())) {
            return Err(invalid_query());
        }
        let mut filters = vec![
            json!({"term":{&self.account_field:get("account")?}}),
            json!({"range":{"@timestamp":{"gte":from.as_str(),"lt":to.as_str()}}}),
        ];
        let mut excluded = Vec::new();
        let mut body = json!({"timeout":"30s","track_total_hits":false,"size":1});
        match call.tool() {
            Tool::SiemSearch => Self::search(call, &mut filters, &mut excluded, &mut body)?,
            Tool::SiemGetAlert => {
                filters.push(json!({"term":{"kibana.alert.uuid":get("alert_id")?}}));
                body["_source"] = json!(false);
                body["fields"] = json!([
                    "@timestamp",
                    "event.*",
                    "user.*",
                    "source.*",
                    "host.*",
                    "cloud.*",
                    "kibana.alert.*",
                    &self.account_field
                ]);
            }
            _ => return Err(invalid_query()),
        }
        body["query"] = json!({"bool":{"filter":filters,"must_not":excluded}});
        Ok(body)
    }
    fn search(
        call: &AuthorizedCall,
        filters: &mut Vec<Value>,
        excluded: &mut Vec<Value>,
        body: &mut Value,
    ) -> Result<(), AppError> {
        let query = SiemQuery::parse(call.proposal_args()).ok_or_else(invalid_query)?;
        let selected = field(query.field());
        let predicate = match query.operator() {
            SiemOperator::Prefix => json!({"prefix":{selected:query.value()}}),
            _ => json!({"term":{selected:query.value()}}),
        };
        if query.operator() == SiemOperator::NotEquals {
            filters.push(json!({"exists":{"field":selected}}));
            excluded.push(predicate);
        } else {
            filters.push(predicate);
        }
        if query.aggregation() == SiemAggregation::Events {
            body["size"] = json!(query.limit());
            body["sort"] = json!([{"@timestamp":"asc"}]);
        } else {
            let group = field(query.group_by().ok_or_else(invalid_query)?);
            body["size"] = json!(0);
            let order = if query.aggregation() == SiemAggregation::Distinct {
                json!({"_key":"asc"})
            } else {
                json!({"_count":"desc"})
            };
            body["aggs"] =
                json!({"groups":{"terms":{"field":group,"size":query.limit(),"order":order}}});
        }
        Ok(())
    }
}
