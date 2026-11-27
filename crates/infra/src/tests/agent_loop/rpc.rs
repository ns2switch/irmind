use super::*;
use irmind_app::AuditEventKind;
use serde_json::{Value, json};
use std::{
    io::{self, Cursor, Read, Write},
    sync::mpsc::{Receiver, Sender, channel},
    thread,
    time::Duration,
};

const MAGIC: &[u8] = b"IRMIND-RPC-V1\0";
const WAIT: Duration = Duration::from_secs(10);

struct Input {
    receive: Receiver<Vec<u8>>,
    buffer: Cursor<Vec<u8>>,
}
impl Read for Input {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.buffer.position() == self.buffer.get_ref().len() as u64 {
            match self.receive.recv() {
                Ok(bytes) => self.buffer = Cursor::new(bytes),
                Err(_) => return Ok(0),
            }
        }
        self.buffer.read(output)
    }
}
struct Output(Sender<Vec<u8>>);
impl Write for Output {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0
            .send(data.to_vec())
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Client {
    send: Sender<Vec<u8>>,
    responses: Receiver<Vec<u8>>,
    id: u32,
}
impl Client {
    fn request(&mut self, method: &str, mut params: Value) -> u32 {
        self.id += 1;
        params.sort_all_objects();
        let body = format!(
            r#"{{"id":{},"method":"{method}","params":{params}}}"#,
            self.id
        );
        let mut frame = u32::try_from(body.len())
            .expect("length")
            .to_be_bytes()
            .to_vec();
        frame.extend_from_slice(body.as_bytes());
        self.send.send(frame).expect("request");
        self.id
    }
    fn read(&self) -> Value {
        let frame = self.responses.recv_timeout(WAIT).expect("protocol output");
        serde_json::from_slice(&frame[4..]).expect("response JSON")
    }
    fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.request(method, params);
        loop {
            let frame = self.read();
            if frame["id"] == id {
                return frame;
            }
            assert!(frame.get("seq").is_some(), "out-of-order reply");
        }
    }
    fn open(&mut self, id: &CaseId) {
        self.open_with(id, MAGIC, 1);
    }

    fn open_with(&mut self, id: &CaseId, magic: &[u8], version: u8) {
        self.send.send(magic.to_vec()).expect("magic");
        assert_eq!(
            self.responses.recv_timeout(WAIT).expect("magic reply"),
            magic
        );
        assert_eq!(
            self.call("hello", json!({"client":"fixture", "version":version}))["result"]["version"],
            version
        );
        let denied = self.call(
            "open_case",
            json!({"case_id":"10000000-0000-4000-8000-000000000002"}),
        );
        assert_eq!(denied["error"]["code"], 3);
        assert_eq!(
            self.call("open_case", json!({"case_id":id.as_str()}))["result"]["case_id"],
            id.as_str()
        );
    }
}

fn connection() -> (Client, Input, Output) {
    let (send, receive) = channel();
    let (outbound, responses) = channel();
    (
        Client {
            send,
            responses,
            id: 0,
        },
        Input {
            receive,
            buffer: Cursor::new(Vec::new()),
        },
        Output(outbound),
    )
}

#[test]
fn engine_rpc_streams_signed_turns_and_keeps_approvals_in_irmind() {
    let (_root, store, engine, id) = engine_fixture();
    let engine = engine.with_case_lifecycle(store.clone());
    let model = ProtocolModel::default();
    let (client, input, output) = connection();
    thread::scope(|scope| {
        let mut client = client;
        let case = id.clone();
        let server_engine = &engine;
        let server_model = &model;
        let server = scope.spawn(move || {
            irmind_app::engine_rpc::serve(
                server_engine,
                case,
                Some(server_model),
                &CancellationToken::new(),
                input,
                output,
            )
        });
        client.open(&id);
        let status = client.call("case_status", json!({"case_id":id.as_str()}));
        assert_eq!(status["result"]["evidence"]["sources"], 0);
        let cursor = status["result"]["cursor"].as_u64().expect("cursor");
        assert_eq!(
            client.call(
                "subscribe",
                json!({"after":cursor+1, "case_id":id.as_str()})
            )["error"]["code"],
            6
        );
        assert_eq!(
            client.call("subscribe", json!({"after":cursor, "case_id":id.as_str()}))["result"]["cursor"],
            cursor
        );
        assert!(client.call("start_turn", json!({"case_id":id.as_str(),"text":"hello"}))["result"]["operation"].is_string());
        let mut prior = cursor;
        loop {
            let event = client.read();
            let seq = event["seq"].as_u64().expect("sequence");
            assert!(seq > prior);
            prior = seq;
            assert_eq!(event["case_id"], id.as_str());
            if event["payload"]["state"] == "answer" {
                assert!(
                    event["payload"]["text"]
                        .as_str()
                        .expect("answer")
                        .contains("summarized")
                );
                assert_eq!(event["payload"]["clipped"], false);
                break;
            }
        }
        client.request("approve", json!({"case_id":id.as_str()}));
        assert!(client.responses.recv_timeout(WAIT).is_err());
        assert_eq!(
            server
                .join()
                .expect("server thread")
                .expect_err("unknown method closes")
                .kind(),
            io::ErrorKind::InvalidData
        );
    });
    engine.verify(&id).expect("case custody");
    let entries = store.entries(&id).expect("audit");
    assert!(
        entries
            .iter()
            .any(|entry| entry.kind == irmind_app::AuditEventKind::FinalAnswer)
    );
    assert!(
        !entries
            .iter()
            .any(|entry| entry.kind == irmind_app::AuditEventKind::ApprovalGranted)
    );
}

struct BlockingModel(Sender<()>);
#[async_trait]
impl LlmPort for BlockingModel {
    async fn complete(
        &self,
        _: CompletionRequest,
        cancel: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        self.0.send(()).expect("waiter");
        cancel.cancelled().await;
        Err(AppError::Cancelled)
    }
}

#[test]
fn engine_rpc_cancel_is_bound_to_the_active_operation_and_audited() {
    let (_root, store, engine, id) = engine_fixture();
    let engine = engine.with_case_lifecycle(store.clone());
    let (entered, called) = channel();
    let model = BlockingModel(entered);
    let (client, input, output) = connection();
    thread::scope(|scope| {
        let mut client = client;
        let case = id.clone();
        let server_engine = &engine;
        let server_model = &model;
        let server = scope.spawn(move || {
            irmind_app::engine_rpc::serve(
                server_engine,
                case,
                Some(server_model),
                &CancellationToken::new(),
                input,
                output,
            )
        });
        client.open(&id);
        let started = client.call("start_turn", json!({"case_id":id.as_str(),"text":"hello"}));
        let operation = started["result"]["operation"].as_str().expect("operation");
        called.recv_timeout(WAIT).expect("model active");
        assert_eq!(
            client.call(
                "cancel",
                json!({"case_id":id.as_str(),"operation":"10000000-0000-4000-8000-000000000003"})
            )["error"]["code"],
            5
        );
        assert_eq!(
            client.call(
                "cancel",
                json!({"case_id":id.as_str(),"operation":operation})
            )["result"]["accepted"],
            true
        );
        drop(client);
        server.join().expect("server thread").expect("server");
    });
    engine.verify(&id).expect("case custody");
    assert!(
        store
            .operations(&id)
            .expect("operations")
            .iter()
            .any(|entry| entry.operation == "investigation")
    );
}

struct BackpressuredOutput {
    output: Output,
    blocked: Sender<()>,
    resume: Receiver<()>,
}
impl Write for BackpressuredOutput {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let model_requested = data
            .get(4..)
            .and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok())
            .is_some_and(|frame| frame["payload"]["state"] == "model_requested");
        if model_requested {
            self.blocked
                .send(())
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
            self.resume.recv().map_err(|_| io::ErrorKind::BrokenPipe)?;
        }
        self.output.write(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

#[test]
fn engine_rpc_backpressure_cancels_an_in_flight_turn() {
    let (_root, store, engine, id) = engine_fixture();
    let engine = engine.with_case_lifecycle(store.clone());
    let (entered, called) = channel();
    let model = BlockingModel(entered);
    let (mut client, input, output) = connection();
    let (blocked, waiting) = channel();
    let (unblock, resume) = channel();
    let (ended, result) = channel();
    thread::scope(|scope| {
        let case = id.clone();
        let engine = &engine;
        let model = &model;
        let server = scope.spawn(move || {
            let result = irmind_app::engine_rpc::serve(
                engine,
                case,
                Some(model),
                &CancellationToken::new(),
                input,
                BackpressuredOutput {
                    output,
                    blocked,
                    resume,
                },
            );
            ended.send(result).expect("server completion");
        });
        client.open(&id);
        client.call("subscribe", json!({"after":0, "case_id":id.as_str()}));
        client.call("start_turn", json!({"case_id":id.as_str(),"text":"hello"}));
        called.recv_timeout(WAIT).expect("active model");
        waiting.recv_timeout(WAIT).expect("writer blocked");
        let ended_while_blocked = result.recv_timeout(WAIT);
        unblock.send(()).expect("release the fixture writer");
        drop(client);
        server.join().expect("server thread");
        assert_eq!(
            ended_while_blocked
                .expect("server didn't wait on client")
                .expect_err("write timeout")
                .kind(),
            io::ErrorKind::TimedOut,
        );
    });
    engine.verify(&id).expect("case custody");
    assert!(
        store
            .operations(&id)
            .expect("operations")
            .iter()
            .any(|entry| entry.operation == "investigation")
    );
}

#[test]
fn engine_rpc_projects_pending_approval_without_its_arguments_or_authority() {
    let (_root, store, engine, id) = engine_fixture();
    let port = FakeExternalIntel {
        calls: Mutex::new(0),
    };
    let model = ObedientModel {
        seen: Mutex::new(Vec::new()),
    };
    let engine = engine
        .with_threat_intel(&port)
        .with_case_lifecycle(store.clone());
    let (client, input, output) = connection();
    thread::scope(|scope| {
        let mut client = client;
        let case = id.clone();
        let server_engine = &engine;
        let server_model = &model;
        let server = scope.spawn(move || {
            irmind_app::engine_rpc::serve(
                server_engine,
                case,
                Some(server_model),
                &CancellationToken::new(),
                input,
                output,
            )
        });
        client.open(&id);
        assert_eq!(
            client.call("subscribe", json!({"after":0, "case_id":id.as_str()}))["result"]["cursor"],
            0
        );
        assert!(
            client.call(
                "start_turn",
                json!({"case_id":id.as_str(),"text":"Investigate this synthetic alert"})
            )["result"]["operation"]
                .is_string()
        );
        loop {
            let event = client.read();
            if event["kind"] == "approval_state" {
                assert_eq!(event["payload"], json!({"state":"review_in_tui"}));
                break;
            }
        }
        assert_eq!(*port.calls.lock().expect("provider calls"), 0);
        client.request(
            "request_approval_prompt",
            json!({"case_id":id.as_str(),"proposal":"a".repeat(64)}),
        );
        let result = server.join().expect("server thread");
        assert_eq!(
            result.expect_err("unavailable method closes").kind(),
            io::ErrorKind::InvalidData
        );
    });
    engine.verify(&id).expect("case custody");
    assert_eq!(
        engine.pending_approvals(&id).expect("approval queue").len(),
        1
    );
    assert_eq!(*port.calls.lock().expect("provider calls"), 0);
}

struct NoPlanPreview;
impl irmind_app::subagents::AnalystPlanInteraction for NoPlanPreview {
    fn review<'a>(
        &'a self,
        _: &'a irmind_app::subagents::SafePlanPreview,
        _: &'a CancellationToken,
    ) -> irmind_app::subagents::PortFuture<'a, irmind_app::subagents::AnalystPlanChoice> {
        Box::pin(async { panic!("stdio must never review a delegation plan") })
    }
}

struct RequestsDelegation;
#[async_trait]
impl LlmPort for RequestsDelegation {
    async fn complete(
        &self,
        request: CompletionRequest,
        _: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        assert!(request.tools.iter().any(|tool| tool.name == "skill_read"));
        assert!(
            !request
                .tools
                .iter()
                .any(|tool| tool.name == "delegate_task")
        );
        let denied = request.messages.iter().any(|message| {
            message.tool_call_id.as_deref() == Some("synthetic_delegation")
                && message.content.contains("Delegation is unavailable")
        });
        let calls = if denied {
            Vec::new()
        } else {
            vec![ModelToolCall::from_proposal(
                "synthetic_delegation",
                ProposedCall {
                    tool: Tool::DelegateTask,
                    args: BTreeMap::from([("tasks".into(), "[]".into())]),
                },
            )?]
        };
        Ok(irmind_app::single_completion_stream(
            ModelResponse {
                text: "Synthetic skill turn".into(),
                calls,
                raw: "synthetic frame".into(),
                truncated: false,
            },
            None,
        ))
    }
}

fn engine_with_subagents_and_skill() -> (tempfile::TempDir, Arc<LocalStore>, Engine<'static>) {
    use irmind_app::{SkillServices, subagents::SubagentPorts};
    let root = tempfile::tempdir().expect("temporary case root");
    let store = Arc::new(open_source_store(root.path()).expect("local store"));
    let parquet = Arc::new(crate::ParquetStore::open(root.path()).expect("Parquet store"));
    let analyst = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[61; 32]),
        actor: Actor::Analyst,
    });
    let agent = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[62; 32]),
        actor: Actor::Agent(irmind_domain::AgentId::parse("skills-agent").expect("agent ID")),
    });
    let verifier = LocalVerifier::from_signer(analyst.as_ref())
        .with_trusted_key(&agent.actor(), &agent.public_key())
        .expect("trusted agent");
    let services = SkillServices::new(
        Arc::new(crate::FileSkillPackageStore::new(root.path())),
        Arc::new(crate::TomlSkillCompiler),
        agent,
        crate::bundled_skill_candidates()
            .expect("bundled skills")
            .into_iter()
            .filter(|skill| skill.metadata().name().as_str() == "windows-triage")
            .map(|skill| skill.package().clone())
            .collect(),
    )
    .expect("skill services");
    let engine = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(analyst, Arc::new(verifier)),
            Arc::new(MandatoryGuard::new().expect("guard")),
        )
        .with_subagents(SubagentPorts {
            branches: parquet,
            queries: store.task_evidence_queries(store.source_evidence_reader()),
            analyst: Arc::new(NoPlanPreview),
        }),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .expect("engine")
    .with_case_lifecycle(store.clone())
    .with_skills(services)
    .expect("trusted skill signer");
    (root, store, engine)
}

#[test]
fn no_delegation_in_engine_rpc_even_after_loading_a_skill() {
    let (_root, store, engine) = engine_with_subagents_and_skill();
    let id = engine.create_case("Synthetic", "local").expect("case").id;
    let (client, input, output) = connection();
    thread::scope(|scope| {
        let mut client = client;
        let case = id.clone();
        let server_engine = &engine;
        let server = scope.spawn(move || {
            irmind_app::engine_rpc::serve(
                server_engine,
                case,
                Some(&RequestsDelegation),
                &CancellationToken::new(),
                input,
                output,
            )
        });
        client.open(&id);
        client.call("subscribe", json!({"after":0,"case_id":id.as_str()}));
        client.call(
            "start_turn",
            json!({"case_id":id.as_str(),"text":"/windows-triage"}),
        );
        loop {
            if client.read()["payload"]["state"] == "answer" {
                break;
            }
        }
        drop(client);
        server.join().expect("server thread").expect("server");
    });
    engine.verify(&id).expect("case custody");
    let entries = store.entries(&id).expect("audit");
    assert!(
        entries
            .iter()
            .any(|entry| entry.kind == AuditEventKind::SkillLoadV1)
    );
    assert!(
        !entries
            .iter()
            .any(|entry| entry.kind == AuditEventKind::SubagentPlanV2)
    );
}

mod passphrase;
