use crate::contract_support::contract_runtime;
use crate::*;
use std::fmt::Write as _;

pub struct MockResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub location: Option<&'static str>,
    pub delay: Duration,
    pub headers: Vec<(&'static str, &'static str)>,
}

impl MockResponse {
    #[must_use]
    pub fn json(body: &str) -> Self {
        Self {
            status: 200,
            body: body.as_bytes().to_vec(),
            location: None,
            delay: Duration::ZERO,
            headers: Vec::new(),
        }
    }
    #[must_use]
    pub fn status(status: u16) -> Self {
        Self {
            status,
            body: b"{}".to_vec(),
            location: None,
            delay: Duration::ZERO,
            headers: Vec::new(),
        }
    }
    #[must_use]
    pub fn redirect() -> Self {
        Self {
            status: 302,
            body: Vec::new(),
            location: Some("/unexpected-redirect"),
            delay: Duration::ZERO,
            headers: Vec::new(),
        }
    }

    #[must_use]
    pub fn delayed(body: &str, delay: Duration) -> Self {
        Self {
            delay,
            ..Self::json(body)
        }
    }

    #[must_use]
    pub fn with_header(mut self, name: &'static str, value: &'static str) -> Self {
        self.headers.push((name, value));
        self
    }
}

#[derive(Debug)]
pub struct RecordedRequest {
    pub method: String,
    pub target: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

pub struct MockServer {
    origin: String,
    task: JoinHandle<Result<Vec<RecordedRequest>, String>>,
}

/// Every reqwest adapter uses this builder and bounded-body contract.
pub fn run_http_safety_contract() -> Result<(), String> {
    let runtime = contract_runtime()?;
    let redirect = MockServer::start(vec![MockResponse::redirect()])?;
    // A short wall-clock timeout races with Windows runner scheduling while the
    // suite compiles and runs in parallel. The delayed fixture still proves it.
    let client = irmind_http::client_builder(Duration::from_secs(1), false)
        .build()
        .map_err(|error| error.to_string())?;
    let status = runtime
        .block_on(async { client.get(redirect.origin()).send().await })
        .map_err(|error| error.to_string())?
        .status();
    if !status.is_redirection() || redirect.finish()?.len() != 1 {
        return Err("HTTP client followed a redirect".into());
    }
    let delayed = MockServer::start(vec![MockResponse::delayed("{}", Duration::from_secs(3))])?;
    let timed_out = runtime.block_on(async { client.get(delayed.origin()).send().await });
    if !timed_out.is_err_and(|error| error.is_timeout()) || delayed.finish()?.len() != 1 {
        return Err("HTTP client did not enforce its timeout".into());
    }
    let large = MockServer::start(vec![MockResponse::json(&"X".repeat(1_025))])?;
    let response = runtime
        .block_on(async { client.get(large.origin()).send().await })
        .map_err(|error| error.to_string())?;
    let result = runtime.block_on(irmind_http::read_limited(
        response,
        1_024,
        &CancellationToken::new(),
    ));
    if result != Err(irmind_http::BodyError::TooLarge) || large.finish()?.len() != 1 {
        return Err("HTTP body limit was not enforced".into());
    }
    Ok(())
}

impl MockServer {
    pub fn start(script: Vec<MockResponse>) -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
        listener
            .set_nonblocking(true)
            .map_err(|error| error.to_string())?;
        let port = listener
            .local_addr()
            .map_err(|error| error.to_string())?
            .port();
        let task = thread::spawn(move || serve(&listener, &script));
        Ok(Self {
            origin: format!("http://127.0.0.1:{port}/"),
            task,
        })
    }
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
    pub fn finish(self) -> Result<Vec<RecordedRequest>, String> {
        self.task
            .join()
            .map_err(|_| "mock HTTP server thread failed".to_owned())?
    }
}

fn serve(listener: &TcpListener, script: &[MockResponse]) -> Result<Vec<RecordedRequest>, String> {
    let mut requests = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut quiet_until = if script.is_empty() {
        Some(Instant::now() + Duration::from_millis(80))
    } else {
        None
    };
    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "mock server received {} of {} expected requests",
                requests.len(),
                script.len()
            ));
        }
        if quiet_until.is_some_and(|until| Instant::now() >= until) {
            return Ok(requests);
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                if requests.len() >= script.len() {
                    return Err("EDR followed a redirect or made an unexpected request".into());
                }
                // Accepted sockets can inherit nonblocking mode on macOS and Windows.
                stream
                    .set_nonblocking(false)
                    .map_err(|error| error.to_string())?;
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .map_err(|error| error.to_string())?;
                let request = read_request(&stream)?;
                let response = &script[requests.len()];
                requests.push(request);
                write_response(&mut stream, response)?;
                if requests.len() == script.len() {
                    quiet_until = Some(Instant::now() + Duration::from_millis(80));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn read_request(stream: &TcpStream) -> Result<RecordedRequest, String> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|error| error.to_string())?;
    if line.len() > 8192 {
        return Err("mock request line too long".into());
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or("missing method")?.to_owned();
    let target = parts.next().ok_or("missing target")?.to_owned();
    let mut headers = BTreeMap::new();
    for _ in 0..64 {
        line.clear();
        reader
            .read_line(&mut line)
            .map_err(|error| error.to_string())?;
        if line == "\r\n" || line == "\n" {
            break;
        }
        if line.is_empty() || line.len() > 8192 {
            return Err("malformed mock request headers".into());
        }
        let (name, value) = line
            .split_once(':')
            .ok_or("malformed mock request header")?;
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let len = headers
        .get("content-length")
        .map_or(Ok(0), |value| value.parse::<usize>())
        .map_err(|error| error.to_string())?;
    if len > 65_536 {
        return Err("mock request body too large".into());
    }
    let mut body = vec![0; len];
    reader
        .read_exact(&mut body)
        .map_err(|error| error.to_string())?;
    Ok(RecordedRequest {
        method,
        target,
        headers,
        body,
    })
}

fn write_response(stream: &mut TcpStream, response: &MockResponse) -> Result<(), String> {
    if !response.delay.is_zero() {
        thread::sleep(response.delay);
    }
    let reason = match response.status {
        200 => "OK",
        302 => "Found",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let location = response
        .location
        .map_or(String::new(), |url| format!("Location: {url}\r\n"));
    let mut extra = String::new();
    for (name, value) in &response.headers {
        write!(&mut extra, "{name}: {value}\r\n").map_err(|error| error.to_string())?;
    }
    let head = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{location}{extra}Connection: close\r\n\r\n",
        response.status,
        response.body.len()
    );
    if let Err(error) = stream.write_all(head.as_bytes()) {
        if !response.delay.is_zero() && error.kind() == std::io::ErrorKind::BrokenPipe {
            return Ok(());
        }
        return Err(error.to_string());
    }
    stream
        .write_all(&response.body)
        .map_err(|error| error.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn accepted_socket_waits_for_request_bytes() {
        let server = MockServer::start(vec![MockResponse::json("{}")]).unwrap();
        let address = server
            .origin()
            .strip_prefix("http://")
            .unwrap()
            .trim_end_matches('/');
        let mut client = TcpStream::connect(address).unwrap();
        thread::sleep(Duration::from_millis(30));
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
        assert_eq!(server.finish().unwrap().len(), 1);
    }
}
