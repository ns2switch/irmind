use super::{DomainError, Reader, put};
use sha2::{Digest, Sha256};

pub const ARTIFACT_V2_SCOPE_KEYS: &str = "scope-partitions-v1";
pub const ARTIFACT_V2_PARTITION_POLICY: &str = "nfkc-unicode-18.0.0-ascii-v1";
pub const ARTIFACT_V2_MAX_KEY_VALUES: u16 = 1024;
pub const ARTIFACT_V2_INITIAL_HOST_CAP: u16 = 64;
pub const ARTIFACT_V2_MAX_DATE_TUPLES: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ScopePartitionKey {
    Account,
    Cluster,
    Host,
    Region,
    Tenant,
}

impl ScopePartitionKey {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Cluster => "cluster",
            Self::Host => "host",
            Self::Region => "region",
            Self::Tenant => "tenant",
        }
    }
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "account" => Ok(Self::Account),
            "host" => Ok(Self::Host),
            "region" => Ok(Self::Region),
            _ => Err(DomainError::InvalidManifest),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum PartitionOverflowReason {
    Cardinality,
    TupleBudget,
    UnrepresentableValue,
}

impl PartitionOverflowReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cardinality => "cardinality",
            Self::TupleBudget => "tuple-budget",
            Self::UnrepresentableValue => "unrepresentable-value",
        }
    }
    fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "cardinality" => Ok(Self::Cardinality),
            "tuple-budget" => Ok(Self::TupleBudget),
            "unrepresentable-value" => Ok(Self::UnrepresentableValue),
            _ => Err(DomainError::InvalidManifest),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ScopePartitionValue {
    Ordinary(String),
    Overflow(PartitionOverflowReason),
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ScopePartitionV2 {
    pub key: ScopePartitionKey,
    pub cap: u16,
    pub value: ScopePartitionValue,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ArtifactPartitionV2 {
    pub date: String,
    pub key_set: String,
    pub policy: String,
    pub tuple_cap: u64,
    pub all_scope_overflow: bool,
    pub scopes: Vec<ScopePartitionV2>,
}

impl ArtifactPartitionV2 {
    pub fn validate(&self) -> Result<(), DomainError> {
        let date_valid = self.date == "unknown"
            || (self.date.len() == 10
                && crate::UtcTimestamp::parse(&format!("{}T00:00:00Z", self.date)).is_ok());
        if !date_valid
            || self.key_set != ARTIFACT_V2_SCOPE_KEYS
            || self.policy != ARTIFACT_V2_PARTITION_POLICY
            || self.tuple_cap != ARTIFACT_V2_MAX_DATE_TUPLES
            || self.scopes.len() > 5
            || !self
                .scopes
                .windows(2)
                .all(|p| p[0].key.as_str() < p[1].key.as_str())
            || (self.all_scope_overflow && self.scopes.is_empty())
        {
            return Err(DomainError::InvalidManifest);
        }
        for scope in &self.scopes {
            if matches!(
                scope.key,
                ScopePartitionKey::Cluster | ScopePartitionKey::Tenant
            ) || !(1..=ARTIFACT_V2_MAX_KEY_VALUES).contains(&scope.cap)
                || (self.all_scope_overflow
                    && scope.value
                        != ScopePartitionValue::Overflow(PartitionOverflowReason::TupleBudget))
            {
                return Err(DomainError::InvalidManifest);
            }
            if !self.all_scope_overflow
                && scope.value
                    == ScopePartitionValue::Overflow(PartitionOverflowReason::TupleBudget)
            {
                return Err(DomainError::InvalidManifest);
            }
            if let ScopePartitionValue::Ordinary(value) = &scope.value
                && !valid_normalized_value(value)
            {
                return Err(DomainError::InvalidManifest);
            }
        }
        Ok(())
    }

    /// Only fixed keys, checked dates and generated hashes/discriminators become paths.
    pub fn path_prefix(&self) -> Result<String, DomainError> {
        self.validate()?;
        let mut path = format!("date={}/", self.date);
        if self.all_scope_overflow {
            return Ok(format!("{path}scope=overflow-tuple-budget/"));
        }
        for scope in &self.scopes {
            let component = match &scope.value {
                ScopePartitionValue::Ordinary(value) => scope_hash(scope.key, value),
                ScopePartitionValue::Overflow(reason) => {
                    format!("overflow-{}-cap{}", reason.as_str(), scope.cap)
                }
            };
            path.push_str(scope.key.as_str());
            path.push('=');
            path.push_str(&component);
            path.push('/');
        }
        Ok(path)
    }

    pub(in crate::custody_manifest) fn write(&self, out: &mut Vec<u8>) {
        for value in [&self.date, &self.key_set, &self.policy] {
            put(out, value.as_bytes());
        }
        out.extend_from_slice(&self.tuple_cap.to_be_bytes());
        out.push(u8::from(self.all_scope_overflow));
        out.extend_from_slice(&(self.scopes.len() as u64).to_be_bytes());
        for scope in &self.scopes {
            put(out, scope.key.as_str().as_bytes());
            out.extend_from_slice(&u64::from(scope.cap).to_be_bytes());
            match &scope.value {
                ScopePartitionValue::Ordinary(value) => {
                    out.push(0);
                    put(out, value.as_bytes());
                }
                ScopePartitionValue::Overflow(reason) => {
                    out.push(1);
                    put(out, reason.as_str().as_bytes());
                }
            }
        }
    }

    pub(in crate::custody_manifest) fn read(reader: &mut Reader<'_>) -> Result<Self, DomainError> {
        let date = reader.string_limit(10)?;
        let key_set = reader.string_limit(128)?;
        let policy = reader.string_limit(128)?;
        let tuple_cap = reader.u64()?;
        let all_scope_overflow = reader.bool()?;
        let count = reader.u64()?;
        if count > 5 {
            return Err(DomainError::InvalidManifest);
        }
        let mut scopes = Vec::new();
        for _ in 0..count {
            let key = ScopePartitionKey::parse(&reader.string_limit(16)?)?;
            let cap = u16::try_from(reader.u64()?).map_err(|_| DomainError::InvalidManifest)?;
            let value = match reader.byte()? {
                0 => ScopePartitionValue::Ordinary(reader.string_limit(128)?),
                1 => ScopePartitionValue::Overflow(PartitionOverflowReason::parse(
                    &reader.string_limit(32)?,
                )?),
                _ => return Err(DomainError::InvalidManifest),
            };
            scopes.push(ScopePartitionV2 { key, cap, value });
        }
        let result = Self {
            date,
            key_set,
            policy,
            tuple_cap,
            all_scope_overflow,
            scopes,
        };
        result.validate()?;
        Ok(result)
    }
}

fn valid_normalized_value(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._:@-".contains(&b))
}

fn scope_hash(key: ScopePartitionKey, value: &str) -> String {
    let mut bytes = b"irmind-scope-partition-v1\0".to_vec();
    for field in [ARTIFACT_V2_SCOPE_KEYS, key.as_str(), value] {
        put(&mut bytes, field.as_bytes());
    }
    let digest = Sha256::digest(bytes);
    let digits = super::super::HEX_DIGITS;
    digest
        .iter()
        .flat_map(|byte| {
            [
                char::from(digits[usize::from(byte >> 4)]),
                char::from(digits[usize::from(byte & 15)]),
            ]
        })
        .collect()
}
