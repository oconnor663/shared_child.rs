use std::io;
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::process::Child;
use std::time::Instant;
use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{WaitForSingleObject, INFINITE};

pub struct Handle(RawHandle);

// Kind of like a child PID on Unix, it's important not to keep the handle
// around after the child has been cleaned up. The best solution would be to
// have the handle actually borrow the child, but we need to keep the child
// unborrowed. Instead we just avoid storing them.
pub fn get_handle(child: &Child) -> Handle {
    Handle(child.as_raw_handle())
}

// This is very similar to libstd's Child::wait implementation, because the
// basic wait on Windows doesn't reap. The main difference is that this can be
// called without &mut Child.
pub fn wait_without_reaping(handle: Handle) -> io::Result<()> {
    wait_deadline_without_reaping(handle, None)
}

pub fn wait_deadline_without_reaping(
    handle: Handle,
    maybe_deadline: Option<Instant>,
) -> io::Result<()> {
    let timeout_ms: u32 = if let Some(deadline) = maybe_deadline {
        let timeout = deadline.saturating_duration_since(Instant::now());
        // Convert to milliseconds, rounding *up*. (That way we don't repeatedly sleep for 0ms when
        // we're close to the timeout.)
        (timeout.as_nanos().saturating_add(999_999) / 1_000_000)
            .try_into()
            .unwrap_or(u32::MAX)
    } else {
        INFINITE
    };
    let wait_ret = unsafe { WaitForSingleObject(handle.0 as HANDLE, timeout_ms) };
    if wait_ret != WAIT_OBJECT_0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
