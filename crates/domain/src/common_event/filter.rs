use super::{EntityRole, EventCategory, EventHeaderV1, EventOutcome, EventType};

/// Typed predicates do not interpret source text or extend policy scope.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CommonEventFilter {
    pub category: Option<EventCategory>,
    pub event_type: Option<EventType>,
    pub outcome: Option<EventOutcome>,
    pub role: Option<EntityRole>,
}
impl CommonEventFilter {
    pub const fn is_empty(self) -> bool {
        self.category.is_none()
            && self.event_type.is_none()
            && self.outcome.is_none()
            && self.role.is_none()
    }
    pub fn matches_header(self, header: &EventHeaderV1) -> bool {
        self.category
            .is_none_or(|category| header.categories().contains(category))
            && self
                .event_type
                .is_none_or(|event_type| header.types().contains(event_type))
            && self
                .outcome
                .is_none_or(|outcome| outcome == header.outcome())
    }
}
