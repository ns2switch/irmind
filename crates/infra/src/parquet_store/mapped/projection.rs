use super::super::{AppError, invalid_source};

pub(in crate::parquet_store) fn route_from_path(path: &str) -> Result<Option<&str>, AppError> {
    let Some((_, route)) = path.rsplit_once(".map-") else {
        return Ok(None);
    };
    let route = route.strip_suffix(".parquet").ok_or_else(invalid_source)?;
    if route.len() != 64
        || !route
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid_source());
    }
    Ok(Some(route))
}
