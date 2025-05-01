use std::io;
use std::process::Child;

// A handle on Unix is just the PID.
pub struct Handle(u32);

pub fn get_handle(child: &Child) -> Handle {
    Handle(child.id())
}

// This blocks until a child exits, without reaping the child.
pub fn wait_without_reaping(handle: Handle) -> io::Result<()> {
    loop {
        let ret = unsafe {
            let mut siginfo = std::mem::zeroed();
            libc::waitid(
                libc::P_PID,
                handle.0 as libc::id_t,
                &mut siginfo,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if ret == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
        // We were interrupted. Loop and retry.
    }
}
