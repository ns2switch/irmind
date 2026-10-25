#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

mod approvals;
mod canonical;
mod entities;
mod ids;
mod policy;
mod tainted;
use canonical::{canonical_args, put, take_field, take_u64};

pub use approvals::*;
pub use entities::*;
use entities::{valid_scope_target, valid_scope_time};
pub use ids::*;
pub use policy::*;
pub use tainted::*;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
