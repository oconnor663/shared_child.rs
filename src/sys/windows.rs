use std::io;
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::process::Child;
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
    let wait_ret = unsafe { WaitForSingleObject(handle.0 as HANDLE, INFINITE) };
    if wait_ret != WAIT_OBJECT_0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
