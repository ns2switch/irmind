//! The local engine protocol transports bounded projections and turn requests.
//! The caller has already admitted a case on the analyst's local terminal.
use crate::{AppError, CancellationToken, CancelledOperation, CaseId, Engine, LlmPort};
use approvals::{Approvals, Protocol};
use serde_json::{Value, json};
use std::{
    io::{self, Read, Write},
    sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel},
    thread::{self, Scope, ScopedJoinHandle},
    time::{Duration, Instant},
};
use uuid::Uuid;

mod approvals;
mod case;
mod wire;
use wire::{Fault, Method, Request, params};

const POLL: Duration = Duration::from_millis(250);
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const IDLE_TIMEOUT: Duration = Duration::from_mins(2);
const MAX_CLIENT_TEXT: usize = 8 * 1024;

pub fn canonical_case_id(text: &str) -> Result<CaseId, AppError> {
    if !wire::canonical_uuid(text) {
        return Err(AppError::InvalidCaseId);
    }
    CaseId::parse(text).map_err(|_| AppError::InvalidCaseId)
}

/// Serve a single explicitly admitted local session on inherited pipes. The
/// caller owns terminal access. The protocol never performs an approval.
pub fn serve(
    engine: &Engine<'_>,
    admitted: CaseId,
    model: Option<&dyn LlmPort>,
    shutdown: &CancellationToken,
    input: impl Read + Send + 'static,
    output: impl Write + Send + 'static,
) -> io::Result<()> {
    serve_protocol(
        engine,
        admitted,
        model,
        shutdown,
        Protocol::V1,
        input,
        output,
    )
}

/// The host binds this verifier to the active encrypted file keystore.
pub type PassphraseVerifier<'a> = dyn Fn(&secrecy::SecretString, &[u8]) -> bool + Sync + 'a;

/// IRMind-only callbacks. A protocol client cannot supply an authenticator.
#[derive(Clone, Copy, Default)]
pub struct ApprovalAuthenticators<'a> {
    pub passphrase: Option<&'a PassphraseVerifier<'a>>,
    pub windows_hello: Option<&'a WindowsHelloVerifier<'a>>,
    pub touch_id: Option<TouchIdAuthenticator<'a>>,
}

#[derive(Clone, Copy)]
pub struct TouchIdAuthenticator<'a> {
    /// Capacity proven for the current native display configuration.
    pub title_limit_utf16: u16,
    pub verify: &'a TouchIdVerifier<'a>,
}

pub type TouchIdVerifier<'a> = dyn Fn(&str, Instant, &CancellationToken) -> bool + Sync + 'a;

pub type WindowsHelloVerifier<'a> =
    dyn Fn(&str, &str, Instant, &CancellationToken) -> bool + Sync + 'a;

/// RPC V2 is selected before either peer writes the protocol magic. The
/// caller must give this transport unbuffered private inherited pipes.
pub fn serve_v2(
    engine: &Engine<'_>,
    admitted: CaseId,
    model: Option<&dyn LlmPort>,
    shutdown: &CancellationToken,
    authenticators: ApprovalAuthenticators<'_>,
    input: impl Read + Send + 'static,
    output: impl Write + Send + 'static,
) -> io::Result<()> {
    serve_protocol(
        engine,
        admitted,
        model,
        shutdown,
        Protocol::V2(authenticators),
        input,
        output,
    )
}

fn serve_protocol(
    engine: &Engine<'_>,
    admitted: CaseId,
    model: Option<&dyn LlmPort>,
    shutdown: &CancellationToken,
    protocol: Protocol<'_>,
    mut input: impl Read + Send + 'static,
    mut output: impl Write + Send + 'static,
) -> io::Result<()> {
    let session_shutdown = shutdown.child_token();
    let peer_shutdown = session_shutdown.clone();
    let v2 = protocol.v2();
    let magic = protocol.magic();
    let (requests, incoming) = sync_channel(4);
    // A blocking pipe read must not keep a cancelled case or a turn alive.
    // The CLI process owns these two I/O threads. They hold no engine state.
    thread::Builder::new()
        .name("irmind-rpc-read".into())
        .spawn(move || {
            let _disconnect = v2.then(|| peer_shutdown.drop_guard());
            if wire::read_magic(&mut input, magic).is_err() {
                let _ = requests.send(Err(()));
                return;
            }
            loop {
                match wire::request(&mut input, v2) {
                    Ok(Some(request)) => {
                        if requests.send(Ok(request)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => return,
                    Err(_) => {
                        let _ = requests.send(Err(()));
                        return;
                    }
                }
            }
        })?;
    let (outgoing, responses) = sync_channel::<WriteRequest>(1);
    thread::Builder::new()
        .name("irmind-rpc-write".into())
        .spawn(move || {
            for (bytes, done) in responses {
                let result = wire::flush(&mut output, &bytes);
                let failed = result.is_err();
                if done.send(result).is_err() || failed {
                    return;
                }
            }
        })?;
    let output = Output(outgoing);
    output.write(magic.to_vec())?;
    thread::scope(|scope| {
        let mut session = Session {
            engine,
            model,
            admitted,
            open: None,
            active: None,
            id: Uuid::new_v4(),
            last_request: 0,
            shutdown: session_shutdown,
            protocol,
            approvals: Approvals::default(),
        };
        let outcome = session.run(scope, &incoming, &output);
        session.shutdown.cancel();
        // Keep the case lease through cancellation and settlement. The pipe
        // threads do not borrow the engine or keep the lease alive.
        if let Some(turn) = session.active.take() {
            let _ = turn.worker.join();
        }
        session.approvals.finish();
        outcome
    })
}

type WriteRequest = (Vec<u8>, SyncSender<io::Result<()>>);
struct Output(SyncSender<WriteRequest>);
impl Output {
    fn write(&self, bytes: Vec<u8>) -> io::Result<()> {
        let (notify, done) = sync_channel(1);
        self.0
            .try_send((bytes, notify))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "engine client disconnected"))?;
        done.recv_timeout(WRITE_TIMEOUT).map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "engine client did not read its response",
            )
        })?
    }

    fn reply(&self, id: u32, result: Result<Value, Fault>) -> io::Result<()> {
        let reply = match result {
            Ok(value) => json!({"id":id, "result":value, "error":null}),
            Err(fault) => {
                let (code, message) = fault.wire();
                json!({"id":id, "result":null, "error":{"code":code, "message":message}})
            }
        };
        self.write(wire::frame(reply)?)
    }
}

struct Turn<'scope> {
    id: Uuid,
    cancel: CancellationToken,
    worker: ScopedJoinHandle<'scope, Result<String, AppError>>,
}

struct Session<'scope, 'env, 'ports> {
    engine: &'env Engine<'ports>,
    model: Option<&'env dyn LlmPort>,
    admitted: CaseId,
    open: Option<case::OpenCase>,
    active: Option<Turn<'scope>>,
    id: Uuid,
    last_request: u32,
    shutdown: CancellationToken,
    protocol: Protocol<'env>,
    approvals: Approvals<'scope>,
}

impl<'scope, 'env: 'scope> Session<'scope, 'env, '_> {
    fn run(
        &mut self,
        scope: &'scope Scope<'scope, 'env>,
        incoming: &Receiver<Result<Request, ()>>,
        output: &Output,
    ) -> io::Result<()> {
        let mut last_activity = Instant::now();
        while !self.shutdown.is_cancelled()
            && (self.active.is_some() || last_activity.elapsed() < IDLE_TIMEOUT)
        {
            match incoming.recv_timeout(POLL) {
                Ok(Ok(request)) => {
                    self.reap();
                    self.approvals.reap();
                    let id = request.id;
                    let reply = self.request(scope, request);
                    let close = matches!(reply, Err(Fault::Invalid | Fault::Version));
                    output.reply(id, reply)?;
                    if close {
                        break;
                    }
                    last_activity = Instant::now();
                }
                Ok(Err(())) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid IRMind RPC request",
                    ));
                }
                Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => (),
            }
            self.reap();
            self.approvals.reap();
            self.emit(output)?;
        }
        Ok(())
    }

    fn request(
        &mut self,
        scope: &'scope Scope<'scope, 'env>,
        request: Request,
    ) -> Result<Value, Fault> {
        let first = self.last_request == 0;
        if request.id <= self.last_request || first != matches!(request.method, Method::Hello) {
            return Err(Fault::Invalid);
        }
        self.last_request = request.id;
        match request.method {
            Method::ApprovalPrepare
            | Method::ApprovalSubmit
            | Method::ApprovalStatus
            | Method::ApprovalCancel => self.approval_request(scope, request),
            Method::Hello => {
                let hello = params::<wire::Hello>(request.params)?;
                if hello.version != self.protocol.version() {
                    return Err(Fault::Version);
                }
                if !(1..=64).contains(&hello.client.len())
                    || !hello.client.bytes().all(|b| (0x20..=0x7e).contains(&b))
                {
                    return Err(Fault::Invalid);
                }
                Ok(json!({"version":self.protocol.version(), "session":self.id.to_string()}))
            }
            Method::OpenCase => {
                let input = params::<wire::Case>(request.params)?;
                self.scope(&input.case_id)?;
                if self.open.is_some() {
                    return Err(Fault::Busy);
                }
                self.open = Some(case::admit(self.engine, &self.admitted, &self.shutdown)?);
                Ok(json!({"case_id":self.admitted.as_str(), "anchor":0}))
            }
            Method::CaseStatus => {
                let input = params::<wire::Case>(request.params)?;
                self.require_open(&input.case_id)?;
                if self.active.is_some() || self.approvals.busy() {
                    return Err(Fault::Busy);
                }
                let (cursor, status) = case::status(self.engine, &self.admitted, &self.shutdown)
                    .map_err(Fault::from)?;
                let current = self.open.as_mut().ok_or(Fault::Scope)?;
                current.cursor = cursor;
                current.subscription = None;
                current.needs_status = false;
                Ok(status)
            }
            Method::Subscribe => {
                let input = params::<wire::Subscribe>(request.params)?;
                self.require_open(&input.case_id)?;
                let current = self.open.as_mut().ok_or(Fault::Scope)?;
                if current.needs_status || input.after != current.cursor {
                    return Err(Fault::Resync);
                }
                current.subscription = Some(case::Subscription::new(input.after));
                Ok(json!({"cursor":input.after}))
            }
            Method::StartTurn => {
                let input = params::<wire::StartTurn>(request.params)?;
                self.require_open(&input.case_id)?;
                self.start_turn(scope, input.text)
            }
            Method::Cancel => {
                let input = params::<wire::Cancel>(request.params)?;
                self.require_open(&input.case_id)?;
                if !wire::canonical_uuid(&input.operation) {
                    return Err(Fault::Invalid);
                }
                let turn = self
                    .active
                    .as_ref()
                    .filter(|turn| turn.id.to_string() == input.operation)
                    .ok_or(Fault::Expired)?;
                turn.cancel.cancel();
                Ok(json!({"accepted":true}))
            }
        }
    }

    fn start_turn(
        &mut self,
        scope: &'scope Scope<'scope, 'env>,
        text: String,
    ) -> Result<Value, Fault> {
        if text.is_empty() || text.len() > MAX_CLIENT_TEXT {
            return Err(Fault::Invalid);
        }
        if self.active.is_some() || self.approvals.busy() {
            return Err(Fault::Busy);
        }
        let model = self.model.ok_or(Fault::Scope)?;
        let case = self
            .engine
            .repo
            .get_case(&self.admitted)
            .map_err(Fault::from)?;
        if case.sealed
            || self
                .engine
                .case_scope_exceeds_policy(&case)
                .map_err(Fault::from)?
        {
            return Err(Fault::Scope);
        }
        let target = self.admitted.clone();
        let engine = self.engine;
        let cancel = self.shutdown.child_token();
        let worker_cancel = cancel.clone();
        let id = Uuid::new_v4();
        let worker = thread::Builder::new()
            .name("irmind-rpc-turn".into())
            .spawn_scoped(scope, move || {
                let result = engine.investigate_from_stdio(&target, &text, model, &worker_cancel);
                if matches!(result, Err(AppError::Cancelled)) {
                    engine.record_cancellation(&target, CancelledOperation::Investigation)?;
                }
                result
            })
            .map_err(|_| Fault::Busy)?;
        self.active = Some(Turn { id, cancel, worker });
        Ok(json!({"operation":id.to_string()}))
    }

    fn reap(&mut self) {
        if self
            .active
            .as_ref()
            .is_some_and(|turn| turn.worker.is_finished())
            && let Some(turn) = self.active.take()
        {
            let _ = turn.worker.join();
        }
    }

    fn emit(&mut self, output: &Output) -> io::Result<()> {
        let Some(open) = &mut self.open else {
            return Ok(());
        };
        let Some(subscribed) = &mut open.subscription else {
            return Ok(());
        };
        match subscribed.next(self.engine, &self.admitted, &self.shutdown) {
            Ok(Some(frame)) => {
                output.write(frame.bytes)?;
                open.cursor = open.cursor.max(frame.seq);
                if frame.resync {
                    open.subscription = None;
                    open.needs_status = true;
                }
            }
            Ok(None) => (),
            Err(Fault::Cancelled) => return Ok(()),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "engine event stream unavailable",
                ));
            }
        }
        Ok(())
    }

    fn scope(&self, id: &str) -> Result<(), Fault> {
        let case = canonical_case_id(id).map_err(|_| Fault::Invalid)?;
        if case == self.admitted {
            Ok(())
        } else {
            Err(Fault::Scope)
        }
    }

    fn require_open(&self, id: &str) -> Result<(), Fault> {
        self.scope(id)?;
        self.open.as_ref().map(|_| ()).ok_or(Fault::Scope)
    }
}

impl From<AppError> for Fault {
    fn from(error: AppError) -> Self {
        match error {
            AppError::Cancelled => Self::Cancelled,
            AppError::CaseLifecycle(crate::CaseLifecycleError::Busy) => Self::Busy,
            _ => Self::Scope,
        }
    }
}
