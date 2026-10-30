#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphRecord {
    pub index: usize,
    pub at: String,
    pub event: String,
    pub text: String,
    pub entities: Vec<(String, String)>,
    pub relations: Vec<GraphRelation>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct GraphRelation {
    pub from_kind: String,
    pub from_value: String,
    pub relation: String,
    pub to_kind: String,
    pub to_value: String,
}

#[derive(Clone, Debug)]
pub struct TimelineEvent {
    pub at: String,
    pub event: String,
    pub evidence_hash: String,
    pub record_index: usize,
}
