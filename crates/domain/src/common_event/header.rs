use super::{CategorySet, EventKind, EventOutcome, EventSchemaError, EventText, EventTypeSet};

/// Classification is explicit; an absent mapping has empty sets and unknown outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventHeaderV1 {
    categories: CategorySet,
    types: EventTypeSet,
    outcome: EventOutcome,
    kind: EventKind,
    action: Option<EventText>,
    code: Option<EventText>,
    id: Option<EventText>,
    dataset: Option<EventText>,
}

impl EventHeaderV1 {
    pub const fn new(
        categories: CategorySet,
        types: EventTypeSet,
        outcome: EventOutcome,
        kind: EventKind,
    ) -> Self {
        Self {
            categories,
            types,
            outcome,
            kind,
            action: None,
            code: None,
            id: None,
            dataset: None,
        }
    }
    pub fn with_action(mut self, value: &str) -> Result<Self, EventSchemaError> {
        self.action = Some(EventText::identifier(value)?);
        Ok(self)
    }
    pub fn with_code(mut self, value: &str) -> Result<Self, EventSchemaError> {
        self.code = Some(EventText::identifier(value)?);
        Ok(self)
    }
    pub fn with_id(mut self, value: &str) -> Result<Self, EventSchemaError> {
        self.id = Some(EventText::identifier(value)?);
        Ok(self)
    }
    pub fn with_dataset(mut self, value: &str) -> Result<Self, EventSchemaError> {
        self.dataset = Some(EventText::identifier(value)?);
        Ok(self)
    }
    pub(super) fn json_bytes(&self) -> usize {
        1024 + [&self.action, &self.code, &self.id, &self.dataset]
            .into_iter()
            .flatten()
            .map(EventText::json_bytes)
            .sum::<usize>()
    }
    pub const fn categories(&self) -> CategorySet {
        self.categories
    }
    pub const fn types(&self) -> EventTypeSet {
        self.types
    }
    pub const fn outcome(&self) -> EventOutcome {
        self.outcome
    }
    pub const fn kind(&self) -> EventKind {
        self.kind
    }
    pub fn action(&self) -> Option<&str> {
        self.action.as_ref().map(EventText::as_str)
    }
    pub fn code(&self) -> Option<&str> {
        self.code.as_ref().map(EventText::as_str)
    }
    pub fn id(&self) -> Option<&str> {
        self.id.as_ref().map(EventText::as_str)
    }
    pub fn dataset(&self) -> Option<&str> {
        self.dataset.as_ref().map(EventText::as_str)
    }
}
impl Default for EventHeaderV1 {
    fn default() -> Self {
        Self::new(
            CategorySet::default(),
            EventTypeSet::default(),
            EventOutcome::Unknown,
            EventKind::Event,
        )
    }
}
