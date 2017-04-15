extern crate winapi;
extern crate kernel32;

use std::io;
use std::os::windows::io::{RawHandle, AsRawHandle};
use std::process::Child;

pub struct Handle(RawHandle);

// Similar to what the stdlib does:
// https://github.com/rust-lang/rust/blob/1.15.1/src/libstd/sys/windows/handle.rs#L37-L38
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

// Kind of like a child PID on Unix, it's important not to keep the handle
// around after the child has been cleaned up. The best solution would be to
// have the handle actually borrow the child, but we need to keep the child
// unborrowed. Instead we just store these next to the child, and don't expose
// them publicly.
pub fn get_handle(child: &Child) -> Handle {
    Handle(child.as_raw_handle())
}

// This is very similar to libstd's Child::wait implementation, because the
// basic wait on Windows doesn't reap. The main difference is that this can be
// called without &mut Child.
pub fn wait_without_reaping(handle: &Handle) -> io::Result<()> {
    let wait_ret = unsafe { kernel32::WaitForSingleObject(handle.0, winapi::INFINITE) };
    if wait_ret != winapi::WAIT_OBJECT_0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn try_wait_without_reaping(handle: &Handle) -> io::Result<bool> {
    let wait_ret = unsafe { kernel32::WaitForSingleObject(handle.0, 0) };
    if wait_ret == winapi::WAIT_OBJECT_0 {
        // Child has exited.
        Ok(true)
    } else if wait_ret == winapi::WAIT_TIMEOUT {
        // Child has not exited yet.
        Ok(false)
    } else {
        Err(io::Error::last_os_error())
    }
}
