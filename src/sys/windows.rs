use std::io;
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::process::Child;
use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Threading::{WaitForSingleObject, INFINITE};

#[derive(Copy, Clone)]
pub struct Handle(RawHandle);

// Kind of like a child PID on Unix, it's important not to keep the handle
// around after the child has been cleaned up. The best solution would be to
// have the handle actually borrow the child, but we need to keep the child
// unborrowed. Instead we just avoid storing them.
pub fn get_handle(child: &Child) -> Handle {
    Handle(child.as_raw_handle())
}

// This is very similar to libstd's Child::wait implementation, because the basic wait on Windows
// doesn't reap. (There's no such thing as reaping child processes on Windows. Instead, you close
// the child handle when you're done with it, like a file. These function names are just for
// consistency with the Unix side of things).  The main difference is that this can be called
// without &mut Child.
pub fn wait_noreap(handle: Handle) -> io::Result<()> {
    let wait_ret = unsafe { WaitForSingleObject(handle.0 as HANDLE, INFINITE) };
    match wait_ret {
        WAIT_OBJECT_0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

pub fn try_wait_noreap(handle: Handle) -> io::Result<bool> {
    let wait_ret = unsafe { WaitForSingleObject(handle.0 as HANDLE, 0) };
    if wait_ret == WAIT_OBJECT_0 {
        // The child has exited.
        Ok(true)
    } else if wait_ret == WAIT_TIMEOUT {
        // The child has not exited yet.
        Ok(false)
    } else {
        Err(io::Error::last_os_error())
    }
}

// Return `true` if the child exits before the deadline, otherwise `false`.
//
// Again there's no such thing as "reaping" a child process on Windows, and these function names is
// just for consistency with the Unix side of things.
#[cfg(feature = "timeout")]
pub fn wait_deadline_noreap(handle: Handle, deadline: std::time::Instant) -> io::Result<bool> {
    // If `dwMilliseconds` is `u32::MAX`, `WaitForSingleObject` interprets that as `INFINITE`, so
    // the maximum non-infinite timeout is `u32::MAX - 1`. See:
    // https://docs.rs/windows-sys/latest/windows_sys/Win32/System/Threading/constant.INFINITE.html
    const MAX_DWMILLISECONDS: u32 = u32::MAX - 1;

    // `MAX_DWMILLISECONDS` is about 49.7 days. For timeouts longer than that, we need to loop. We
    // don't have a unit test that exercises this, so to double check changes here, artificially
    // shorten the maximum and put in some prints.
    loop {
        let timeout = deadline.saturating_duration_since(std::time::Instant::now());

        // Convert to milliseconds, rounding *up*. (That way we don't repeatedly sleep for 0ms when
        // we're close to the timeout.)
        let timeout_ms = timeout.as_nanos().saturating_add(999_999) / 1_000_000;

        // Cap the timeout and call `WaitForSingleObject`.
        let capped_wait_ms = std::cmp::min(timeout_ms, MAX_DWMILLISECONDS as u128) as u32;
        let wait_ret = unsafe { WaitForSingleObject(handle.0 as HANDLE, capped_wait_ms) };
        match wait_ret {
            WAIT_OBJECT_0 => return Ok(true),
            WAIT_TIMEOUT => {
                if (capped_wait_ms as u128) < timeout_ms {
                    // We weren't able to do the whole wait. Keep looping.
                    continue;
                }
                return Ok(false);
            }
            _ => return Err(io::Error::last_os_error()),
        }
    }
}
