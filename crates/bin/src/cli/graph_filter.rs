use super::{Result, anyhow};
use irmind_app::GraphQueryFilter;

#[derive(clap::Args, Clone, Default)]
pub(crate) struct GraphFilterArgs {
    #[arg(long)]
    from: Option<String>,
    #[arg(long)]
    to: Option<String>,
    #[arg(long)]
    account: Option<String>,
    #[arg(long)]
    project: Option<String>,
    #[arg(long)]
    region: Option<String>,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    event_category: Option<String>,
    #[arg(long)]
    event_type: Option<String>,
    #[arg(long)]
    event_outcome: Option<String>,
    #[arg(long)]
    entity_role: Option<String>,
}

impl GraphFilterArgs {
    pub(super) fn parse(&self) -> Result<GraphQueryFilter> {
        let mut args = std::collections::BTreeMap::new();
        for (name, value) in [
            ("from", &self.from),
            ("to", &self.to),
            ("account", &self.account),
            ("project", &self.project),
            ("region", &self.region),
            ("host", &self.host),
            ("event_category", &self.event_category),
            ("event_type", &self.event_type),
            ("event_outcome", &self.event_outcome),
            ("entity_role", &self.entity_role),
        ] {
            if let Some(value) = value {
                args.insert(name.into(), value.clone());
            }
        }
        GraphQueryFilter::from_args(&args).map_err(|_| anyhow!("invalid graph query filter"))
    }
}
