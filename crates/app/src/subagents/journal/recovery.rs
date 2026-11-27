//! Conservative reconciliation reads authenticated state; it never retries I/O.
use super::{SubagentDigest, SubagentJournal, SubagentRecord, SubagentRecordError};
use crate::subagents::{
    ReservationPurpose, StartedSubagentPlan, SubagentCheckpointV1, SubagentReservationV1,
    SubagentResources, SubagentResultV1,
};

pub(in crate::subagents) struct TaskRecovery {
    pub checkpoints: Vec<SubagentCheckpointV1>,
    pub completed: Option<SubagentResultV1>,
    pub usage: SubagentResources,
    pub reservations: Vec<SubagentDigest>,
    pub unsettled: Vec<(SubagentReservationV1, Option<SubagentDigest>)>,
}

pub(in crate::subagents) struct PlanRecovery {
    pub plan: crate::subagents::SubagentPlanV2,
    pub entry_hash: SubagentDigest,
    pub allocation: Option<SubagentReservationV1>,
    pub needs_hold: bool,
}

impl SubagentJournal {
    pub(in crate::subagents) fn plan_is_open(
        &self,
        identity: SubagentDigest,
    ) -> Result<bool, SubagentRecordError> {
        if self.failed {
            return Err(SubagentRecordError);
        }
        Ok(self
            .plans
            .get(&identity)
            .is_some_and(super::ledger::PlanLedger::is_open))
    }

    pub(in crate::subagents) fn recovery_plans(
        &self,
    ) -> Result<Vec<PlanRecovery>, SubagentRecordError> {
        if self.failed {
            return Err(SubagentRecordError);
        }
        let mut ordered = self
            .plans
            .values()
            .filter(|state| state.is_open())
            .collect::<Vec<_>>();
        ordered.sort_by_key(|state| state.seq);
        ordered
            .into_iter()
            .map(|state| {
                Ok(PlanRecovery {
                    plan: state.plan.clone(),
                    entry_hash: state.entry_hash(),
                    allocation: state.recovery_allocation()?,
                    needs_hold: state.needs_preview_hold(),
                })
            })
            .collect()
    }

    pub(in crate::subagents) fn task_recovery(
        &self,
        started: &StartedSubagentPlan,
        task: SubagentDigest,
    ) -> Result<TaskRecovery, SubagentRecordError> {
        let state = self
            .plans
            .get(&started.plan.identity()?)
            .ok_or(SubagentRecordError)?;
        if self.failed
            || state.is_preview()
            || !state.is_open()
            || state.allocation() != Some(started.allocation.identity()?)
            || state.plan.canonical()? != started.plan.canonical()?
            || !state.plan.tasks.iter().any(|spec| spec.task_id == task)
        {
            return Err(SubagentRecordError);
        }
        let mut recovery = TaskRecovery {
            checkpoints: state.checkpoints.get(&task).cloned().unwrap_or_default(),
            completed: state.results.get(&task).cloned(),
            usage: SubagentResources::default(),
            reservations: Vec::new(),
            unsettled: Vec::new(),
        };
        for (reservation, settled) in state.recovery_requests(task) {
            let accounting =
                if settled.is_none() && reservation.purpose != ReservationPurpose::Model {
                    self.recover_dispatch(&reservation)?
                } else {
                    None
                };
            // A missing provider report is never guessed or released. The full
            // reservation remains charged, including a crash after dispatch.
            let amount = settled.unwrap_or(reservation.amount);
            recovery.usage = recovery.usage.checked_add(amount)?;
            recovery.reservations.push(reservation.operation_id);
            if settled.is_none() {
                recovery.unsettled.push((reservation, accounting));
            }
        }
        recovery.reservations.sort();
        Ok(recovery)
    }

    fn recover_dispatch(
        &self,
        reservation: &SubagentReservationV1,
    ) -> Result<Option<SubagentDigest>, SubagentRecordError> {
        let mut result = None;
        for (hash, accounted) in &self.accounting {
            let Some(attribution) = &accounted.attribution else {
                continue;
            };
            if Some(attribution.task_id) == reservation.task_id
                && attribution.reservation_sha256 == reservation.identity()?
                && !self.accounted.contains(&(*hash, reservation.purpose))
                && result.replace(*hash).is_some()
            {
                return Err(SubagentRecordError);
            }
        }
        Ok(result)
    }
}
