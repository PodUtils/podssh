//! The request of an upgrade on Windows (T-678), which has no SIGUSR2: an
//! event of this user's session named by the node's root pid
//! (`podssh-node-upgrade-PID`, the pid of its run's record), which a node
//! waits for while it serves and `podssh update` sets.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{CreateEventW, OpenEventW, SetEvent, WaitForSingleObject, EVENT_MODIFY_STATE};

/// How often the waiting thread looks whether the node stopped waiting.
const STEP: Duration = Duration::from_millis(500);

/// The event's name for the node whose root is `pid`, as UTF-16 with its NUL.
pub fn name(pid: u32) -> Vec<u16> {
    format!("podssh-node-upgrade-{pid}").encode_utf16().chain(Some(0)).collect()
}

/// A node's wait for the request: each request is one message on the
/// receiver; the wait ends when the guard drops.
pub struct Wait {
    stop: Arc<AtomicBool>,
}

impl Drop for Wait {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Wait for the requests of an upgrade of the node whose root is `pid`;
/// `None` when the event cannot be made.
pub fn watch(pid: u32) -> Option<(Wait, tokio::sync::mpsc::UnboundedReceiver<()>)> {
    let name = name(pid);
    // SAFETY: an auto-reset event, unset, with a NUL-terminated name;
    // another process's of the same name is opened.
    let event: HANDLE = unsafe { CreateEventW(std::ptr::null(), 0, 0, name.as_ptr()) };
    if event.is_null() {
        return None;
    }
    let event = event as usize;
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let stopped = stop.clone();
    std::thread::spawn(move || {
        while !stopped.load(Ordering::SeqCst) {
            // SAFETY: the event made above, open until this thread closes it.
            let got = unsafe { WaitForSingleObject(event as HANDLE, STEP.as_millis() as u32) };
            if got == WAIT_OBJECT_0 && tx.send(()).is_err() {
                break;
            }
        }
        // SAFETY: the event made above, which this thread alone holds.
        unsafe { CloseHandle(event as HANDLE) };
    });
    Some((Wait { stop }, rx))
}

/// Ask the node whose root is `pid` to take the binary now in place.
pub fn send(pid: u32) -> Result<(), String> {
    let name = name(pid);
    // SAFETY: a NUL-terminated name; the handle is closed below.
    let event = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, name.as_ptr()) };
    if event.is_null() {
        return Err(format!("it waits for no request ({})", std::io::Error::last_os_error()));
    }
    // SAFETY: the event opened above.
    let set = unsafe { SetEvent(event) };
    let why = std::io::Error::last_os_error();
    // SAFETY: as above.
    unsafe { CloseHandle(event) };
    if set == 0 {
        return Err(why.to_string());
    }
    Ok(())
}
