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
}

impl GraphFilterArgs {
    pub(super) fn parse(&self) -> Result<GraphQueryFilter> {
        GraphQueryFilter::parse_with_host(
            self.from.as_deref(),
            self.to.as_deref(),
            self.account.as_deref(),
            self.project.as_deref(),
            self.region.as_deref(),
            self.host.as_deref(),
        )
        .map_err(|_| anyhow!("invalid graph partition filter"))
    }
}
