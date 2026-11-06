#![cfg(windows)]
//! Service handles stay on one owner thread; callbacks only increment an epoch.
use crate::witness_protocol::denied;
use std::{
    io, ptr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, PSC_NOTIFICATION_REGISTRATION,
    QueryServiceStatusEx, SC_EVENT_STATUS_CHANGE, SC_HANDLE, SC_MANAGER_CONNECT,
    SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS_PROCESS,
    SubscribeServiceChangeNotifications, UnsubscribeServiceChangeNotifications,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Stamp {
    pub(crate) epoch: u64,
    pids: [u32; 2],
}
pub(crate) struct Services {
    send: Option<mpsc::SyncSender<mpsc::SyncSender<io::Result<Stamp>>>>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Services {
    pub(crate) fn new() -> io::Result<Self> {
        let (send, receive) = mpsc::sync_channel::<mpsc::SyncSender<io::Result<Stamp>>>(1);
        let (ready, response) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("evtx-service-watch".into())
            .spawn(move || {
                let initialized = Watch::new();
                let _ = ready.send(initialized.as_ref().map(|_| ()).map_err(|_| denied()));
                if let Ok(watch) = initialized {
                    while let Ok(reply) = receive.recv() {
                        let _ = reply.send(watch.snapshot());
                    }
                }
            })?;
        let owner = Self {
            send: Some(send),
            worker: Some(worker),
        };
        response
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| denied())??;
        Ok(owner)
    }
    pub(crate) fn snapshot(&self) -> io::Result<Stamp> {
        let (reply, receive) = mpsc::sync_channel(1);
        self.send
            .as_ref()
            .ok_or_else(denied)?
            .try_send(reply)
            .map_err(|_| denied())?;
        receive
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| denied())?
    }
}
impl Drop for Services {
    fn drop(&mut self) {
        self.send.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
struct Service(SC_HANDLE);
impl Drop for Service {
    fn drop(&mut self) {
        // SAFETY: this owner holds one SCM/service handle, closed exactly once.
        unsafe { CloseServiceHandle(self.0) };
    }
}
struct Subscription(PSC_NOTIFICATION_REGISTRATION);
impl Drop for Subscription {
    fn drop(&mut self) {
        // SAFETY: live owned registration; waits for callbacks before their retained context is dropped.
        unsafe { UnsubscribeServiceChangeNotifications(self.0) };
    }
}
struct Watch {
    subscriptions: Vec<Subscription>,
    services: Vec<Service>,
    epoch: Arc<AtomicU64>,
}
impl Watch {
    fn new() -> io::Result<Self> {
        // SAFETY: null machine/database select local SCM; query-only connection.
        let manager =
            Service(unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) });
        if manager.0.is_null() {
            return Err(denied());
        }
        let mut out = Self {
            subscriptions: Vec::new(),
            services: Vec::new(),
            epoch: Arc::new(AtomicU64::new(0)),
        };
        for name in ["BFE", "MpsSvc"] {
            let wide = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            // SAFETY: terminated name, live SCM handle and query-status access only.
            let service =
                Service(unsafe { OpenServiceW(manager.0, wide.as_ptr(), SERVICE_QUERY_STATUS) });
            if service.0.is_null() {
                return Err(denied());
            }
            let mut subscription = 0;
            // SAFETY: Arc retains an aligned AtomicU64 until all subscriptions are
            // synchronously removed; callback never blocks or touches other memory.
            let status = unsafe {
                SubscribeServiceChangeNotifications(
                    service.0,
                    SC_EVENT_STATUS_CHANGE,
                    Some(changed),
                    Arc::as_ptr(&out.epoch).cast(),
                    &raw mut subscription,
                )
            };
            if status != 0 {
                return Err(denied());
            }
            out.subscriptions.push(Subscription(subscription));
            out.services.push(service);
        }
        out.snapshot()?;
        Ok(out)
    }
    fn snapshot(&self) -> io::Result<Stamp> {
        let epoch = self.epoch.load(Ordering::SeqCst);
        let mut pids = [0; 2];
        for (index, service) in self.services.iter().enumerate() {
            pids[index] = running(service)?;
        }
        if epoch == u64::MAX || epoch != self.epoch.load(Ordering::SeqCst) {
            return Err(denied());
        }
        Ok(Stamp { epoch, pids })
    }
}
fn running(service: &Service) -> io::Result<u32> {
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0;
    // SAFETY: exact query class, initialized aligned output, matching size and live service handle.
    let ok = unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            (&raw mut status).cast(),
            u32::try_from(std::mem::size_of_val(&status)).map_err(|_| denied())?,
            &raw mut needed,
        )
    };
    if ok == 0 || status.dwCurrentState != SERVICE_RUNNING || status.dwProcessId == 0 {
        return Err(denied());
    }
    Ok(status.dwProcessId)
}
unsafe extern "system" fn changed(_: u32, context: *const std::ffi::c_void) {
    // SAFETY: registration retains this exact aligned Arc allocation until unsubscribe has joined all callbacks.
    let epoch = unsafe { &*context.cast::<AtomicU64>() };
    let _ = epoch.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
        value.checked_add(1)
    });
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn notification_invalidates_a_stamp_even_when_both_services_are_running_again() {
        let watch = Watch::new().unwrap();
        let previous = watch.snapshot().unwrap();
        // SAFETY: the callback receives the same retained Arc allocation as the live subscription.
        unsafe {
            changed(0, Arc::as_ptr(&watch.epoch).cast());
        }
        let current = watch.snapshot().unwrap();
        assert_eq!(previous.pids, current.pids);
        assert_ne!(previous.epoch, current.epoch);
    }
}
