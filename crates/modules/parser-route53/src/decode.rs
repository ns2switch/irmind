use irmind_app::{
    AppError, CancellationToken, FixedAppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceFormatV1, SourceInput, SourceRecordV1, SourceValue,
        framed::{DecodedSourceFrame, decode_json_source},
        json::{JsonFrames, SourceJsonLimits, decode_json_fields},
    },
};
use irmind_domain::{IndexedTime, Tainted};
use std::collections::BTreeMap;

pub struct Route53SourceDecoder;

fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}

fn text<'a>(fields: &'a SourceValue, field: &str) -> Option<&'a str> {
    fields
        .field(field)
        .and_then(SourceValue::as_text)
        .filter(|value| !value.is_empty())
}

fn prepare(fields: SourceValue) -> Result<DecodedSourceFrame, AppError> {
    let minor = text(&fields, "version")
        .and_then(|value| value.strip_prefix("1."))
        .ok_or_else(invalid)?;
    if minor.is_empty()
        || minor.len() > 16
        || !minor.bytes().all(|byte| byte.is_ascii_digit())
        || ![
            "account_id",
            "region",
            "query_name",
            "query_type",
            "srcaddr",
        ]
        .iter()
        .all(|field| text(&fields, field).is_some())
        || !(text(&fields, "vpc_id").is_some() || text(&fields, "resource_id").is_some())
    {
        return Err(invalid());
    }
    let timestamp =
        IndexedTime::from_rfc3339(text(&fields, "query_timestamp").ok_or_else(invalid)?, false)
            .map_err(|_| invalid())?;
    Ok(DecodedSourceFrame {
        fields,
        timestamp: Some(timestamp),
        format: SourceFormatV1::try_new("route53-resolver", super::VERSION, BTreeMap::new())
            .map_err(|_| invalid())?,
    })
}

impl SourceDecoder for Route53SourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: super::PARSER,
            version: super::VERSION,
        }
    }

    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        self.decode_with_budget(DecodeInput::Reader(input), DecodeBudget::sequential(), emit)
    }

    fn decode_with_budget(
        &self,
        input: DecodeInput<'_>,
        budget: DecodeBudget,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        decode_json_source(input.into_reader(), self.identity(), budget, &prepare, emit)
    }
}

pub(super) fn detect(sample: &[u8]) -> bool {
    let cancel = CancellationToken::new();
    let mut reader = std::io::Cursor::new(&sample[..sample.len().min(65_536)]);
    let mut frames = JsonFrames::new(&mut reader, &cancel).without_record_wrappers();
    frames.next_frame().ok().flatten().is_some_and(|frame| {
        !frame.oversized()
            && decode_json_fields(frame.bytes(), SourceJsonLimits::default())
                .is_ok_and(|fields| prepare(fields).is_ok())
    })
}
