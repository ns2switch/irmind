use super::bad;
use irmind_app::{AppError, CancellationToken};
use irmind_process_containment::Child;
use std::{
    io::{BufRead, BufReader, Read},
    sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

enum Message {
    Line(Vec<u8>),
    OutputEnd,
    ErrorEnd,
    Isolation(&'static str),
    Failure,
}
struct Running {
    child: Child,
    receive: Option<Receiver<Message>>,
    threads: Vec<JoinHandle<()>>,
}
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.terminate();
        self.receive.take();
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}
pub(super) fn run(
    mut child: Child,
    budget: u64,
    deadline: Duration,
    cancel: &CancellationToken,
    on_line: &mut dyn FnMut(Vec<u8>) -> Result<(), AppError>,
) -> Result<(), AppError> {
    let stdout = child
        .take_stdout()
        .map_err(|_| bad("EVTX stdout unavailable"))?;
    let stderr = child
        .take_stderr()
        .map_err(|_| bad("EVTX stderr unavailable"))?;
    let (send, receive) = mpsc::sync_channel(2);
    let mut running = Running {
        child,
        receive: Some(receive),
        threads: Vec::new(),
    };
    let output = send.clone();
    running.threads.push(
        thread::Builder::new()
            .name("evtx-output".into())
            .spawn(move || pump(stdout, budget, &output))
            .map_err(|_| bad("EVTX reader cannot start"))?,
    );
    running.threads.push(
        thread::Builder::new()
            .name("evtx-errors".into())
            .spawn(move || drain(stderr, &send))
            .map_err(|_| bad("EVTX error reader cannot start"))?,
    );
    let start = Instant::now();
    let (mut output_done, mut error_done) = (false, false);
    while !output_done || !error_done {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if start.elapsed() > deadline {
            return Err(bad("EVTX helper timed out; no partial file was ingested"));
        }
        match running
            .receive
            .as_ref()
            .ok_or_else(|| bad("EVTX output channel unavailable"))?
            .recv_timeout(Duration::from_millis(25))
        {
            Ok(Message::Line(bytes)) => on_line(bytes)?,
            Ok(Message::OutputEnd) => output_done = true,
            Ok(Message::ErrorEnd) => error_done = true,
            Ok(Message::Isolation(message)) => return Err(bad(message)),
            Ok(Message::Failure) | Err(RecvTimeoutError::Disconnected) => {
                return Err(bad("EVTX helper output failed or exceeded its limit"));
            }
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if start.elapsed() > deadline {
            return Err(bad("EVTX helper did not exit within its time limit"));
        }
        if let Some(success) = running
            .child
            .try_wait()
            .map_err(|_| bad("cannot inspect EVTX helper exit"))?
        {
            return if success {
                Ok(())
            } else {
                Err(AppError::Policy(format!(
                    "EVTX helper exited unsuccessfully ({}); no partial file was ingested; check native sandbox support",
                    running
                        .child
                        .exit_description()
                        .ok()
                        .flatten()
                        .unwrap_or_else(|| "exit status unavailable".into())
                )))
            };
        }
        thread::sleep(Duration::from_millis(10));
    }
}
fn pump(reader: Box<dyn Read + Send>, mut budget: u64, send: &SyncSender<Message>) {
    let mut reader = BufReader::new(reader);
    let mut line = Vec::new();
    loop {
        let Ok(available) = reader.fill_buf() else {
            let _ = send.send(Message::Failure);
            return;
        };
        if available.is_empty() {
            let _ = send.send(if line.is_empty() {
                Message::OutputEnd
            } else {
                Message::Failure
            });
            return;
        }
        let count = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |n| n + 1);
        if count as u64 > budget || line.len().saturating_add(count) > 4 * 1024 * 1024 {
            let _ = send.send(Message::Failure);
            return;
        }
        budget -= count as u64;
        line.extend_from_slice(&available[..count]);
        reader.consume(count);
        if line.last() == Some(&b'\n')
            && send.send(Message::Line(std::mem::take(&mut line))).is_err()
        {
            return;
        }
    }
}
fn drain(mut reader: Box<dyn Read + Send>, send: &SyncSender<Message>) {
    let mut buffer = [0u8; 4096];
    let mut captured = Vec::new();
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => {
                if let Some(reason) = isolation_reason(&captured) {
                    let _ = send.send(Message::Isolation(reason));
                }
                let _ = send.send(Message::ErrorEnd);
                return;
            }
            Ok(n) => {
                if captured.len().saturating_add(n) > 65536 {
                    let _ = send.send(Message::Failure);
                    return;
                }
                captured.extend_from_slice(&buffer[..n]);
            }
            Err(_) => {
                let _ = send.send(Message::Failure);
                return;
            }
        }
    }
}

fn isolation_reason(bytes: &[u8]) -> Option<&'static str> {
    let text = std::str::from_utf8(bytes).ok()?;
    if text.contains("EVTX requires fully enforced Landlock ABI 1") {
        Some(
            "EVTX unavailable: enable Landlock ABI 1 and unprivileged seccomp on Linux 5.13 or newer; Bubblewrap is not required",
        )
    } else if text.contains("EVTX isolation verification failed")
        || text.contains("EVTX network-family isolation failed")
    {
        Some(
            "EVTX unavailable: the native sandbox did not deny foreign reads, runtime writes or network access; check operating-system sandbox support",
        )
    } else if text.contains("EVTX child process isolation") {
        Some(
            "EVTX unavailable: the native sandbox could not verify that child process creation is denied",
        )
    } else if text.contains("EVTX requires an AppContainer token")
        || text.contains("EVTX inherited an unrelated file handle")
    {
        Some(
            "EVTX unavailable: an isolated AppContainer with explicit handles is required on Windows",
        )
    } else {
        None
    }
}
