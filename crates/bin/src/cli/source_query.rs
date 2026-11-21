use super::{AutomationContext, Subcommand, parse_id};
use anyhow::{Result, anyhow};
use irmind_app::source_queries::SourceQueryAllocationV1;

#[derive(Subcommand, Clone)]
pub(crate) enum SourceQueryCommand {
    /// Sign the named source's organization configuration for this installation.
    Adopt { source_id: String },
    /// Allocate scan and retention resources for one case and sign the change.
    Allocate {
        case_id: String,
        #[arg(long)]
        scan_bytes: Option<u64>,
        #[arg(long)]
        retained_rows: u64,
        #[arg(long)]
        retained_bytes: u64,
        #[arg(long)]
        allow_analytics: bool,
        #[arg(long)]
        reason: String,
    },
    /// Sign a change that closes a case's allocation if nothing is committed.
    Disable {
        case_id: String,
        #[arg(long)]
        reason: String,
    },
}

impl AutomationContext<'_, '_> {
    pub(in crate::cli) fn handle_source_query(self, command: SourceQueryCommand) -> Result<bool> {
        match command {
            SourceQueryCommand::Adopt { source_id } => {
                let settings = self.workspace_io.source_query_settings.as_ref().ok_or_else(|| {
                    anyhow!("configure the organization source-query policy before adopting a source")
                })?;
                let operation = self
                    .engine
                    .adopt_source_query_configuration(&settings.adoption(&source_id)?)?;
                println!(
                    "Signed source adoption {}",
                    irmind_app::hex(&operation.hash)
                );
            }
            SourceQueryCommand::Allocate {
                case_id,
                scan_bytes,
                retained_rows,
                retained_bytes,
                allow_analytics,
                reason,
            } => {
                let allocation = SourceQueryAllocationV1 {
                    enabled: true,
                    analytics_allowed: allow_analytics,
                    scan_bytes,
                    retained_rows,
                    retained_bytes,
                };
                self.update_source_query_allocation(&case_id, allocation, &reason)?;
            }
            SourceQueryCommand::Disable { case_id, reason } => {
                self.update_source_query_allocation(
                    &case_id,
                    SourceQueryAllocationV1::default(),
                    &reason,
                )?;
            }
        }
        Ok(false)
    }

    fn update_source_query_allocation(
        &self,
        case_id: &str,
        allocation: SourceQueryAllocationV1,
        reason: &str,
    ) -> Result<()> {
        let changed = self.engine.change_source_query_budget(
            &parse_id(case_id)?,
            allocation,
            reason,
            self.cancel,
        )?;
        println!(
            "{}",
            if changed {
                "Signed source-query allocation"
            } else {
                "Allocation already matches"
            }
        );
        Ok(())
    }
}
