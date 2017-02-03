extern crate libc;

use std::io;
use std::process::{Child, ExitStatus};
use std::sync::Mutex;

pub struct SharedChild {
    pid: u32,

    // This lock provides shared access to kill() and wait(). But this is a
    // *shared* child, so we never hold onto this lock for a blocking wait.
    child: Mutex<Child>,

    // This is the lock that we hold for blocking calls to libc::waitid(), and
    // it's where we save the ExitStatus after we've reaped the child.
    status: Mutex<Option<ExitStatus>>,
}

impl SharedChild {
    pub fn new(child: Child) -> SharedChild {
        SharedChild {
            pid: child.id(),
            child: Mutex::new(child),
            status: Mutex::new(None),
        }
    }

    pub fn wait(&self) -> io::Result<ExitStatus> {
        // First take the status lock. This is a potentially long block, if
        // another thread is already waiting.
        let mut status_lock = self.status.lock().unwrap();

        // If another thread has already waited, return the status it got.
        if let Some(status) = *status_lock {
            return Ok(status);
        }

        // We're the first thread to wait. Use libc::waitid() to block without
        // reaping the child. Not reaping means its safe for another thread to
        // call kill() while we're here, without racing against another process
        // reusing the PID. Continuing to hold the status lock is important,
        // because POSIX doesn't guarantee much about what happens when multiple
        // threads wait at the same time:
        // http://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html#tag_15_13
        waitid_nowait(self.pid)?;

        // After waitid() returns, we know the child has exited. We can wait()
        // without blocking, and then save the status for future callers.
        let status = self.child.lock().unwrap().wait()?;
        *status_lock = Some(status);
        Ok(status)
    }
}

// This blocks until a child exits, without reaping the child.
fn waitid_nowait(pid: u32) -> io::Result<()> {
    loop {
        let ret = unsafe {
            let mut siginfo = std::mem::uninitialized();
            libc::waitid(libc::P_PID,
                         pid as libc::id_t,
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
        // If we were interrupted, loop and retry.
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use super::*;

    #[test]
    fn test_wait() {
        let child = SharedChild::new(Command::new("true").spawn().unwrap());
        let status = child.wait().unwrap();
        assert_eq!(status.code().unwrap(), 0);
    }
}
