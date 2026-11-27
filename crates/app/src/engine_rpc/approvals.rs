use super::{Fault, Method, Request, Session, params, wire};
use crate::{
    CancellationToken,
    approvals::gui::{DecisionState, GuiApproval, GuiApprovalGate},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    thread::{self, Scope, ScopedJoinHandle},
    time::{Duration, Instant},
};
use uuid::Uuid;

const LIFETIME: Duration = Duration::from_mins(1);

#[derive(Clone, Copy)]
pub(super) enum Protocol<'a> {
    V1,
    V2(Option<&'a super::PassphraseVerifier<'a>>),
}

impl Protocol<'_> {
    pub(super) const fn v2(self) -> bool {
        matches!(self, Self::V2(_))
    }

    pub(super) const fn magic(self) -> &'static [u8] {
        if self.v2() {
            wire::MAGIC_V2
        } else {
            wire::MAGIC
        }
    }

    pub(super) const fn version(self) -> u64 {
        if self.v2() { 2 } else { 1 }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum Decision {
    Approve,
    Deny,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepare {
    case_id: String,
    #[serde(deserialize_with = "optional_request_id")]
    request_id: Option<String>,
    decision: Decision,
}

fn optional_request_id<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::deserialize(deserializer)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identify {
    case_id: String,
    presentation: String,
}

#[derive(Default)]
pub(super) struct Approvals<'scope> {
    live: Option<Arc<Presentation>>,
    worker: Option<ScopedJoinHandle<'scope, ()>>,
    failures: VecDeque<Instant>,
}

struct Presentation {
    prepared: GuiApproval,
    gate: GuiApprovalGate,
    id: Uuid,
    decision: Decision,
    digest: String,
    reply: Value,
}

impl Approvals<'_> {
    pub(super) fn reap(&mut self) {
        if self
            .worker
            .as_ref()
            .is_some_and(ScopedJoinHandle::is_finished)
            && let Some(worker) = self.worker.take()
        {
            let result = worker.join();
            if let Some(live) = &self.live
                && let Ok(mut state) = live.gate.state.lock()
            {
                if result.is_err() && *state == DecisionState::Authenticating {
                    *state = DecisionState::Stale;
                } else if *state == DecisionState::ReauthFailed {
                    self.failures.push_back(Instant::now());
                }
            }
        }
    }

    pub(super) fn finish(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }

    pub(super) const fn busy(&self) -> bool {
        self.worker.is_some()
    }
}

impl<'scope, 'env: 'scope> Session<'scope, 'env, '_> {
    pub(super) fn approval_request(
        &mut self,
        scope: &'scope Scope<'scope, 'env>,
        request: Request,
    ) -> Result<Value, Fault> {
        let Protocol::V2(Some(verify)) = self.protocol else {
            return Err(if self.protocol.v2() {
                Fault::ReviewInTui
            } else {
                Fault::Invalid
            });
        };
        match request.method {
            Method::ApprovalPrepare => self.prepare_approval(&params(request.params)?),
            Method::ApprovalSubmit => {
                self.submit_approval(scope, request.submission.ok_or(Fault::Invalid)?, verify)
            }
            Method::ApprovalStatus | Method::ApprovalCancel => self.approval_state(
                &params(request.params)?,
                matches!(request.method, Method::ApprovalCancel),
            ),
            _ => Err(Fault::Invalid),
        }
    }

    fn prepare_approval(&mut self, input: &Prepare) -> Result<Value, Fault> {
        self.require_open(&input.case_id)?;
        if input
            .request_id
            .as_ref()
            .is_some_and(|id| id.len() != 64 || !wire::lowercase_hex(id))
        {
            return Err(Fault::Invalid);
        }
        if self.approvals.busy() || self.active.is_some() {
            return Err(Fault::Busy);
        }
        let now = self.engine.clock.now().map_err(Fault::from)?;
        if let Some(live) = &self.approvals.live
            && !live.gate.expired(now)
            && *live.gate.state.lock().map_err(|_| Fault::Expired)? == DecisionState::Ready
        {
            return if input.decision == live.decision
                && input
                    .request_id
                    .as_deref()
                    .is_none_or(|id| id == live.prepared.request.id)
            {
                Ok(live.reply.clone())
            } else {
                Err(Fault::Busy)
            };
        }
        let prepared = self
            .engine
            .prepare_gui_approval(&self.admitted, input.request_id.as_deref())
            .map_err(|_| Fault::ReviewInTui)?;
        let now = self.engine.clock.now().map_err(Fault::from)?;
        let presentation = Arc::new(Presentation::new(
            prepared,
            input,
            self.id,
            now,
            self.shutdown.child_token(),
        )?);
        let reply = presentation.reply.clone();
        self.approvals.live = Some(presentation);
        Ok(reply)
    }

    fn submit_approval(
        &mut self,
        scope: &'scope Scope<'scope, 'env>,
        input: wire::Submission,
        verify: &'env super::PassphraseVerifier<'env>,
    ) -> Result<Value, Fault> {
        self.require_open(&input.case_id)?;
        if self.active.is_some() || self.approvals.busy() {
            return Err(Fault::Busy);
        }
        let live = self.presentation(&input.presentation)?.clone();
        let now = self.engine.clock.now().map_err(Fault::from)?;
        let mut state = live.gate.state.lock().map_err(|_| Fault::Expired)?;
        if live.gate.expired(now) || *state != DecisionState::Ready {
            return Err(Fault::Expired);
        }
        if input.view_sha256 != live.digest {
            return Err(Fault::Invalid);
        }
        self.approvals.failures.retain(|at| at.elapsed() < LIFETIME);
        if self.approvals.failures.len() >= 3 {
            return Err(Fault::Busy);
        }
        *state = DecisionState::Authenticating;
        drop(state);
        let engine = self.engine;
        let admitted = self.admitted.clone();
        let worker = live.clone();
        let verify_key = thread::Builder::new()
            .name("irmind-rpc-approval".into())
            .spawn_scoped(scope, move || {
                let passphrase = input.passphrase;
                let verified = !worker.gate.cancel.is_cancelled()
                    && verify(&passphrase, &worker.prepared.analyst_key);
                drop(passphrase);
                if verified {
                    let _ = engine.commit_gui_approval(
                        &admitted,
                        &worker.prepared,
                        worker.decision == Decision::Deny,
                        &worker.gate,
                    );
                }
                if let Ok(mut state) = worker.gate.state.lock()
                    && *state == DecisionState::Authenticating
                {
                    *state = match engine.clock.now() {
                        Ok(now) if worker.gate.expired(now) => DecisionState::Expired,
                        _ if worker.gate.cancel.is_cancelled() => DecisionState::Cancelled,
                        _ if verified => DecisionState::Stale,
                        _ => DecisionState::ReauthFailed,
                    };
                }
            });
        if let Ok(worker) = verify_key {
            self.approvals.worker = Some(worker);
        } else {
            if let Ok(mut state) = live.gate.state.lock() {
                *state = DecisionState::Stale;
            }
            return Err(Fault::Busy);
        }
        Ok(json!({"state":DecisionState::Authenticating}))
    }

    fn approval_state(&self, input: &Identify, cancel: bool) -> Result<Value, Fault> {
        self.require_open(&input.case_id)?;
        let live = self.presentation(&input.presentation)?;
        let now = self.engine.clock.now().map_err(Fault::from)?;
        let mut state = live.gate.state.lock().map_err(|_| Fault::Expired)?;
        let active = matches!(*state, DecisionState::Ready | DecisionState::Authenticating);
        if active && live.gate.expired(now) {
            live.gate.cancel.cancel();
            *state = DecisionState::Expired;
        }
        if !cancel {
            return Ok(json!({"state":*state}));
        }
        let cancelled = matches!(*state, DecisionState::Ready | DecisionState::Authenticating);
        if cancelled {
            live.gate.cancel.cancel();
            *state = DecisionState::Cancelled;
        }
        Ok(json!({"cancelled":cancelled}))
    }

    fn presentation(&self, id: &str) -> Result<&Arc<Presentation>, Fault> {
        if !wire::canonical_uuid(id) {
            return Err(Fault::Invalid);
        }
        self.approvals
            .live
            .as_ref()
            .filter(|live| live.id.to_string() == id)
            .ok_or(Fault::Expired)
    }
}

impl Presentation {
    fn new(
        prepared: GuiApproval,
        input: &Prepare,
        session: Uuid,
        now: u64,
        cancel: CancellationToken,
    ) -> Result<Self, Fault> {
        let expires_at = prepared
            .expires_at
            .min(now.saturating_add(LIFETIME.as_secs()));
        if expires_at <= now {
            return Err(Fault::Expired);
        }
        let id = Uuid::new_v4();
        let mut view = json!({
            "action":prepared.request.tool.as_str(), "args":prepared.request.args,
            "case_id":input.case_id, "decision":input.decision,
            "effective_scope":prepared.effective_scope, "expires_at":expires_at,
            "request_id":prepared.request.id,
        });
        let digest = digest_of(b"irmind-gui-approval-view-v1\0", &mut view)?;
        let code = digest_of(
            b"irmind-gui-approval-code-v1\0",
            &mut json!({
                "nonce":crate::hex(&nonce()), "presentation":id.to_string(),
                "session":session.to_string(), "view_sha256":digest,
            }),
        )?;
        let reply = json!({
            "presentation":id.to_string(), "view":view, "view_sha256":digest,
            "code":&code[..16], "methods":["keystore_passphrase"],
        });
        wire::frame(json!({"id":u32::MAX,"result":reply,"error":null}))
            .map_err(|_| Fault::ReviewInTui)?;
        let gate = GuiApprovalGate {
            state: Mutex::new(DecisionState::Ready),
            expires_at,
            end: Instant::now() + Duration::from_secs(expires_at - now),
            cancel,
        };
        Ok(Self {
            prepared,
            gate,
            id,
            decision: input.decision,
            digest,
            reply,
        })
    }
}

fn digest_of(domain: &[u8], json: &mut Value) -> Result<String, Fault> {
    let mut bytes = domain.to_vec();
    bytes.extend(wire::canonical(json).map_err(|_| Fault::ReviewInTui)?);
    Ok(crate::hex(&crate::sha256(&bytes)))
}

fn nonce() -> [u8; 32] {
    let mut nonce = [0; 32];
    for chunk in nonce.chunks_mut(11) {
        let bytes = Uuid::new_v4().into_bytes();
        // Omit the UUID version and variant bytes.
        for (output, fresh) in chunk.iter_mut().zip(bytes[..6].iter().chain(&bytes[9..])) {
            *output = *fresh;
        }
    }
    nonce
}
