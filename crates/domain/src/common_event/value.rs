use super::{EventSchemaError, EventText};
use crate::IndexedTime;
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
}
impl HashAlgorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }
    pub fn parse(value: &str) -> Result<Self, EventSchemaError> {
        match value {
            "md5" => Ok(Self::Md5),
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            _ => Err(EventSchemaError::InvalidValue),
        }
    }
}
#[derive(Clone, Eq, PartialEq)]
pub struct ContentHash {
    algorithm: HashAlgorithm,
    value: EventText,
}
impl ContentHash {
    pub fn new(algorithm: HashAlgorithm, value: &str) -> Result<Self, EventSchemaError> {
        let length = match algorithm {
            HashAlgorithm::Md5 => 32,
            HashAlgorithm::Sha1 => 40,
            HashAlgorithm::Sha256 => 64,
        };
        if value.len() != length || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(EventSchemaError::InvalidValue);
        }
        Ok(Self {
            algorithm,
            value: EventText::identifier(&value.to_ascii_lowercase())?,
        })
    }
    pub const fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }
    pub fn value(&self) -> &str {
        self.value.as_str()
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkDirection {
    Inbound,
    Outbound,
    Internal,
    External,
    Ingress,
    Egress,
    Unknown,
}
impl NetworkDirection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
            Self::Internal => "internal",
            Self::External => "external",
            Self::Ingress => "ingress",
            Self::Egress => "egress",
            Self::Unknown => "unknown",
        }
    }
    pub fn parse(value: &str) -> Result<Self, EventSchemaError> {
        match value {
            "inbound" => Ok(Self::Inbound),
            "outbound" => Ok(Self::Outbound),
            "internal" => Ok(Self::Internal),
            "external" => Ok(Self::External),
            "ingress" => Ok(Self::Ingress),
            "egress" => Ok(Self::Egress),
            "unknown" => Ok(Self::Unknown),
            _ => Err(EventSchemaError::InvalidValue),
        }
    }
}
#[derive(Clone, Eq, PartialEq)]
pub struct EventTextList(Vec<EventText>);
impl EventTextList {
    pub fn new(values: Vec<EventText>) -> Result<Self, EventSchemaError> {
        if values.len() > 16 {
            return Err(EventSchemaError::LimitExceeded);
        }
        Ok(Self(values))
    }
    pub fn values(&self) -> &[EventText] {
        &self.0
    }
}
#[derive(Clone, Eq, PartialEq)]
pub struct DnsAnswer {
    name: EventText,
    record_type: EventText,
    data: EventText,
}
impl DnsAnswer {
    pub fn new(
        name: EventText,
        record_type: EventText,
        data: EventText,
    ) -> Result<Self, EventSchemaError> {
        if name.as_str().len() > 512
            || record_type.as_str().len() > 32
            || name.as_str().chars().any(char::is_control)
            || record_type.as_str().chars().any(char::is_control)
        {
            return Err(EventSchemaError::InvalidValue);
        }
        Ok(Self {
            name,
            record_type,
            data,
        })
    }
    pub fn name(&self) -> &str {
        self.name.as_str()
    }
    pub fn record_type(&self) -> &str {
        self.record_type.as_str()
    }
    pub fn data(&self) -> &str {
        self.data.as_str()
    }
    fn json_bytes(&self) -> usize {
        64 + self.name.json_bytes() + self.record_type.json_bytes() + self.data.json_bytes()
    }
}
#[derive(Clone, Eq, PartialEq)]
pub struct DnsAnswers(Vec<DnsAnswer>);
impl DnsAnswers {
    pub fn new(values: Vec<DnsAnswer>) -> Result<Self, EventSchemaError> {
        if values.len() > 16 {
            return Err(EventSchemaError::LimitExceeded);
        }
        Ok(Self(values))
    }
    pub fn values(&self) -> &[DnsAnswer] {
        &self.0
    }
}
#[derive(Clone, Eq, PartialEq)]
pub enum CommonValue {
    Boolean(bool),
    Text(EventText),
    Unsigned(u64),
    Ip(IpAddr),
    Hash(ContentHash),
    Time(IndexedTime),
    Direction(NetworkDirection),
    TextList(EventTextList),
    DnsAnswers(DnsAnswers),
}
impl CommonValue {
    pub(super) fn json_bytes(&self) -> usize {
        match self {
            Self::Boolean(_) => 5,
            Self::Text(v) => v.json_bytes(),
            Self::Unsigned(_) => 20,
            Self::Ip(_) => 48,
            Self::Hash(_) => 96,
            Self::Time(_) => 64,
            Self::Direction(_) => 16,
            Self::TextList(v) => 2 + v.values().iter().map(|t| 1 + t.json_bytes()).sum::<usize>(),
            Self::DnsAnswers(v) => 2 + v.values().iter().map(|a| 1 + a.json_bytes()).sum::<usize>(),
        }
    }
}
macro_rules! redacted {
    ($($name:ident),+)=>{$(impl std::fmt::Debug for $name {
        fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.write_str(concat!(stringify!($name),"(<redacted>)"))}
    })+};
}
redacted!(
    ContentHash,
    EventTextList,
    DnsAnswer,
    DnsAnswers,
    CommonValue
);
