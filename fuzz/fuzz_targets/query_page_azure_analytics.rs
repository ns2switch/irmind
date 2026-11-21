#![no_main]
use irmind_app::{CancellationToken, source_queries::SourceQueryPageDecoder};
use irmind_mod_query_azure_log_analytics::AzureAnalyticsCaptureDecoder;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|body: &[u8]| {
    let cancel = CancellationToken::new();
    for decoder in [
        AzureAnalyticsCaptureDecoder::SignIn,
        AzureAnalyticsCaptureDecoder::Audit,
        AzureAnalyticsCaptureDecoder::Activity,
    ] {
        let first = decoder.inspect_page(&mut Cursor::new(body), 0, None, &cancel);
        if let Ok(first) = first {
            let _ = decoder.inspect_page(&mut Cursor::new(body), 1, Some(&first.schema), &cancel);
        }
    }
});
