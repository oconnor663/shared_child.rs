extern crate libc;

use std;
use std::io;
use std::process::Child;

// A handle on Unix is just the PID.
pub struct Handle(u32);

pub fn get_handle(child: &Child) -> Handle {
    Handle(child.id())
}

// This blocks until a child exits, without reaping the child.
pub fn wait_without_reaping(handle: &Handle) -> io::Result<()> {
    loop {
        let ret = unsafe {
            let mut siginfo = std::mem::uninitialized();
            libc::waitid(libc::P_PID,
                         handle.0 as libc::id_t,
                         &mut siginfo,
                         libc::WEXITED | libc::WNOWAIT)
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

// This checks whether the child has already exited, without reaping the child.
pub fn try_wait_without_reaping(handle: &Handle) -> io::Result<bool> {
    let mut siginfo: libc::siginfo_t;
    let ret = unsafe {
        siginfo = std::mem::uninitialized();
        libc::waitid(libc::P_PID,
                     handle.0 as libc::id_t,
                     &mut siginfo,
                     libc::WEXITED | libc::WNOWAIT | libc::WNOHANG)
    };
    if ret != 0 {
        // EINTR should be impossible here
        Err(io::Error::last_os_error())
    } else if siginfo.si_signo == libc::SIGCHLD {
        // The child has exited.
        Ok(true)
    } else if siginfo.si_signo == 0 {
        // The child has not exited.
        Ok(false)
    } else {
        // This should be impossible if we've called waitid correctly.
        Err(io::Error::new(io::ErrorKind::Other,
                           format!("unexpected si_signo from waitid: {}", siginfo.si_signo)))
    }
}
