#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphRecord {
    pub index: usize,
    pub at: String,
    pub event: String,
    pub text: String,
    pub entities: Vec<(String, String)>,
    pub relations: Vec<GraphRelation>,
}

/// Additional derived-index metadata; legacy normalized records keep their exact shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedGraphRecord {
    pub record: GraphRecord,
    pub time: Option<crate::IndexedTime>,
    pub source_offset: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct GraphRelation {
    pub from_kind: String,
    pub from_value: String,
    pub relation: String,
    pub to_kind: String,
    pub to_value: String,
}

/// Closed parser-owned capabilities; directory names never select a profile.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PartitionProfile {
    #[default]
    Unpartitioned,
    CloudAccountRegion,
    EndpointHost,
    KubernetesCluster,
}
