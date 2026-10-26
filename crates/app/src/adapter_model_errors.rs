use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AdapterModelError {
    #[error("model: Anthropic API key is empty")]
    AnthropicAPIKeyIsEmpty,
    #[error("model: Anthropic HTTP client unavailable")]
    AnthropicHTTPClientUnavailable,
    #[error("model: Anthropic request failed")]
    AnthropicRequestFailed,
    #[error("model: Anthropic response failed")]
    AnthropicResponseFailed,
    #[error("model: LLM API key is required for a remote endpoint")]
    LLMAPIKeyIsRequiredForARemoteEndpoint,
    #[error("model: delta after content block stop")]
    DeltaAfterContentBlockStop,
    #[error("model: delta without content block")]
    DeltaWithoutContentBlock,
    #[error("model: duplicate content block")]
    DuplicateContentBlock,
    #[error("model: duplicate message_start")]
    DuplicateMessageStart,
    #[error("model: duplicate provider event field")]
    DuplicateProviderEventField,
    #[error("model: duplicate provider usage")]
    DuplicateProviderUsage,
    #[error("model: incomplete provider tool call")]
    IncompleteProviderToolCall,
    #[error("model: invalid Anthropic model ID")]
    InvalidAnthropicModelID,
    #[error("model: invalid LLM base URL")]
    InvalidLLMBaseURL,
    #[error("model: invalid LLM chat endpoint")]
    InvalidLLMChatEndpoint,
    #[error("model: invalid LLM model ID")]
    InvalidLLMModelID,
    #[error("model: invalid content block stop")]
    InvalidContentBlockStop,
    #[error("model: invalid provider block index")]
    InvalidProviderBlockIndex,
    #[error("model: invalid provider content delta")]
    InvalidProviderContentDelta,
    #[error("model: invalid provider tool index")]
    InvalidProviderToolIndex,
    #[error("model: missing completion token usage")]
    MissingCompletionTokenUsage,
    #[error("model: missing input token usage")]
    MissingInputTokenUsage,
    #[error("model: missing output token usage")]
    MissingOutputTokenUsage,
    #[error("model: missing prompt token usage")]
    MissingPromptTokenUsage,
    #[error("model: missing provider choices")]
    MissingProviderChoices,
    #[error("model: missing provider delta")]
    MissingProviderDelta,
    #[error("model: missing provider tool ID")]
    MissingProviderToolID,
    #[error("model: model token budget is empty")]
    ModelTokenBudgetIsEmpty,
    #[error("model: multiple provider choices")]
    MultipleProviderChoices,
    #[error("model: multiple provider data fields")]
    MultipleProviderDataFields,
    #[error("model: non-contiguous content blocks")]
    NonContiguousContentBlocks,
    #[error("model: provider HTTP client unavailable")]
    ProviderHTTPClientUnavailable,
    #[error("model: provider event before message_start")]
    ProviderEventBeforeMessageStart,
    #[error("model: provider event name mismatch")]
    ProviderEventNameMismatch,
    #[error("model: provider input token usage overflow")]
    ProviderInputTokenUsageOverflow,
    #[error("model: provider output after finish")]
    ProviderOutputAfterFinish,
    #[error("model: provider output after message_stop")]
    ProviderOutputAfterMessageStop,
    #[error("model: provider request failed")]
    ProviderRequestFailed,
    #[error("model: provider response failed")]
    ProviderResponseFailed,
    #[error("model: provider stopped unexpectedly")]
    ProviderStoppedUnexpectedly,
    #[error("model: provider stream error")]
    ProviderStreamError,
    #[error("model: provider stream exceeds 2 MB")]
    ProviderStreamExceeds2MB,
    #[error("model: provider stream incomplete")]
    ProviderStreamIncomplete,
    #[error("model: provider stream omitted usage")]
    ProviderStreamOmittedUsage,
    #[error("model: provider tool ID changed")]
    ProviderToolIDChanged,
    #[error("model: tool call without tool_use finish")]
    ToolCallWithoutToolUseFinish,
    #[error("model: tool_use finish without tool call")]
    ToolUseFinishWithoutToolCall,
    #[error("model: unexpected provider choice index")]
    UnexpectedProviderChoiceIndex,
    #[error("model: unexpected provider stream field")]
    UnexpectedProviderStreamField,
    #[error("model: unsupported provider content block")]
    UnsupportedProviderContentBlock,
    #[error("model: unsupported provider event")]
    UnsupportedProviderEvent,
    #[error("model: unsupported provider tool type")]
    UnsupportedProviderToolType,
}
