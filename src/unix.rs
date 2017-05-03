extern crate libc;

use std::io;

pub trait SharedChildExt {
    /// Sends a signal to the child process with `libc::kill`.
    fn send_signal(&self, signal: libc::c_int) -> io::Result<()>;
}

impl SharedChildExt for super::SharedChild {
    fn send_signal(&self, signal: libc::c_int) -> io::Result<()> {
        let status = self.state_lock.lock().unwrap();
        if let super::ChildState::Exited(_) = *status {
            return Ok(());
        }
        // The child is still running. Signal it. Holding the state lock
        // is important to prevent a PID race.
        // This assumes that the wait methods will never hold the child
        // lock during a blocking wait, since we need it to get the pid.
        let pid = self.id() as libc::pid_t;
        match unsafe { libc::kill(pid, signal) } {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use tests::*;
    use SharedChild;
    use super::libc;
    use super::SharedChildExt;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn test_send_signal() {
        let child = SharedChild::spawn(&mut sleep_forever_cmd()).unwrap();
        child.send_signal(libc::SIGABRT).unwrap();
        let status = child.wait().unwrap();
        assert_eq!(Some(libc::SIGABRT), status.signal());
    }
}
