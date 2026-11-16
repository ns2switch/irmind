use super::*;
use irmind_app::{AppError, KeystoreCapability, KeystoreManifest, ModelOutputProfile};
use std::io::{BufRead as _, Read as _, Write as _};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

#[derive(Default)]
struct UnchangedSecrets {
    reads: AtomicUsize,
    writes: AtomicUsize,
}
impl SecretBackend for UnchangedSecrets {
    fn manifest(&self) -> &'static KeystoreManifest {
        &KeystoreManifest {
            id: "synthetic-probe",
            capabilities: &[KeystoreCapability::Secrets],
            interactive_unlock: false,
            headless: true,
            network: false,
            config_fields: &[],
        }
    }
    fn get(&self, _: &str) -> Result<SecretString, AppError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Err(AppError::SecretMissing)
    }
    fn put(&self, _: &str, _: &SecretString) -> Result<(), AppError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Err(AppError::SecretMissing)
    }
    fn delete(&self, _: &str) -> Result<(), AppError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Err(AppError::SecretMissing)
    }
}

#[test]
fn connection_probe_uses_the_unsaved_draft_and_never_writes_credentials() {
    let providers = [
        "llm-openai-compatible",
        #[cfg(feature = "llm-deepseek")]
        "llm-deepseek",
        #[cfg(feature = "llm-openrouter")]
        "llm-openrouter",
        #[cfg(feature = "llm-anthropic")]
        "llm-anthropic",
    ];
    for provider in providers {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/draft/", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let server = serve(listener, provider);
        let secrets = UnchangedSecrets::default();
        let key = SecretString::from("synthetic-draft-key");
        let result = test_model_connection(
            provider,
            &url,
            "unsaved-draft-model",
            Some(&key),
            &secrets,
            ModelOutputProfile::known(128_000, true).unwrap(),
        );
        let (headers, body) = server.join().unwrap().unwrap();
        assert!(result.unwrap().contains("Connection succeeded"));
        let authority = url
            .strip_prefix("http://")
            .unwrap()
            .split('/')
            .next()
            .unwrap();
        assert!(
            headers
                .to_ascii_lowercase()
                .contains(&format!("host: {authority}"))
        );
        assert!(headers.contains("synthetic-draft-key"));
        assert_eq!(body["model"], "unsaved-draft-model");
        let field = if provider == "llm-openrouter" {
            "max_completion_tokens"
        } else {
            "max_tokens"
        };
        assert_eq!(body[field], 128_000);
        assert_eq!(secrets.reads.load(Ordering::SeqCst), 0);
        assert_eq!(secrets.writes.load(Ordering::SeqCst), 0);
        let encoded = body.to_string();
        assert!(encoded.contains("synthetic connection test"));
        assert!(!encoded.contains("UNTRUSTED_"));
    }
}

fn serve(
    listener: TcpListener,
    provider: &'static str,
) -> std::thread::JoinHandle<std::io::Result<(String, serde_json::Value)>> {
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(value) => break value,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "probe did not send a request");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut reader = std::io::BufReader::new(&mut stream);
        let mut headers = String::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            assert!(headers.len() + line.len() < 16_384);
            if line == "\r\n" {
                break;
            }
            headers.push_str(&line);
        }
        let length: usize = headers
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().unwrap())
            })
            .unwrap();
        assert!(length < 16_384);
        let mut body = vec![0; length];
        reader.read_exact(&mut body)?;
        let response = if provider == "llm-anthropic" {
            concat!(
                "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n",
                "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"OK\"}}\n\n",
                "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
                "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\n",
                "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
            )
        } else {
            concat!(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"OK\"},\"finish_reason\":null}]}\n\n",
                "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\n",
                "data: [DONE]\n\n"
            )
        };
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
            response.len()
        )?;
        Ok((
            headers,
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        ))
    })
}
