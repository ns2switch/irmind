use crate::{BTreeMap, DomainError};

pub(crate) fn canonical_args(args: &BTreeMap<String, String>) -> Vec<u8> {
    let mut bytes = (args.len() as u64).to_be_bytes().to_vec();
    for (key, value) in args {
        put(&mut bytes, key.as_bytes());
        put(&mut bytes, value.as_bytes());
    }
    bytes
}

pub(crate) fn put(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

pub(crate) fn take_u64(rest: &mut &[u8]) -> Result<u64, DomainError> {
    let Some(bytes) = rest.get(..8) else {
        return Err(DomainError::InvalidApproval);
    };
    let number = u64::from_be_bytes(bytes.try_into().map_err(|_| DomainError::InvalidApproval)?);
    *rest = &rest[8..];
    Ok(number)
}

pub(crate) fn take_field<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8], DomainError> {
    let length = usize::try_from(take_u64(rest)?).map_err(|_| DomainError::InvalidApproval)?;
    if length > 2048 {
        return Err(DomainError::InvalidApproval);
    }
    let Some(value) = rest.get(..length) else {
        return Err(DomainError::InvalidApproval);
    };
    *rest = &rest[length..];
    Ok(value)
}
