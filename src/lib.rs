extern crate libc;

use std::io;
use std::process::{Child, ExitStatus};
use std::sync::{Condvar, Mutex};

pub struct SharedChild {
    // This lock provides shared access to kill() and wait(), though sometimes
    // we use libc::waitpid() to reap the child instead. This is a *shared*
    // child, so we never hold onto this lock for a blocking wait.
    child: Mutex<Child>,

    // Threads doing blocking waits will wait on this condvar, and the first
    // waiter will call libc::waitid(), to avoid racing against kill().
    status_lock: Mutex<ChildStatus>,
    status_condvar: Condvar,
}

impl SharedChild {
    pub fn new(child: Child) -> SharedChild {
        SharedChild {
            status_lock: Mutex::new(NotWaiting(child.id())),
            status_condvar: Condvar::new(),
            child: Mutex::new(child),
        }
    }

    /// Wait for the child to exit, blocking the current thread, and return its
    /// exit status.
    pub fn wait(&self) -> io::Result<ExitStatus> {
        let mut status = self.status_lock.lock().unwrap();
        let child_pid;
        loop {
            match *status {
                NotWaiting(pid) => {
                    // No one is waiting on the child yet. That means we need to
                    // do it ourselves. Break out of the loop.
                    child_pid = pid;
                    break;
                }
                Waiting => {
                    // Another thread is already waiting on the child. We wait
                    // for it to signal us on the condvar, then match again,
                    // until we get Exited. Spurious wakeups could bring us here
                    // multiple times though, see the Condvar docs.
                    status = self.status_condvar.wait(status).unwrap();
                }
                Exited(exit_status) => return Ok(exit_status),
            }
        }

        // If we get here, we're the thread responsible for waiting on the
        // child. Put ourselves in the Waiting state and then release the status
        // lock, so that calls to try_wait/kill can go through while we wait.
        *status = Waiting;
        drop(status);

        // Use libc::waitid() to block without reaping the child. Not reaping
        // means it's safe for another thread to call kill() while we're here,
        // without racing against another process reusing the PID. Having only
        // one thread really waiting on the child at a time is important,
        // because POSIX doesn't guarantee much about what happens when multiple
        // threads wait at the same time:
        // http://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html#tag_15_13
        waitid_nowait(child_pid)?;

        // After waitid() returns, the child has exited. We take the status lock
        // again knowing that Child::wait() isn't going to block for very long,
        // and after we've reaped the child we put ourselves in the Exited state
        // and signal other waiters.
        let mut status = self.status_lock.lock().unwrap();
        let exit_status = self.child.lock().unwrap().wait()?;
        *status = Exited(exit_status);
        self.status_condvar.notify_all();
        Ok(exit_status)
    }

    /// Return the child's exit status if it has already exited. If the child is
    /// still running, return `Ok(None)`.
    pub fn try_wait(&self) -> io::Result<Option<ExitStatus>> {
        let mut status = self.status_lock.lock().unwrap();
        let child_pid;

        // Unlike wait() above, we don't loop on the Condvar here. If the status
        // is Waiting or Exited, we return immediately. However, if the status
        // is NotWaiting, we'll do a non-blocking wait below, in case the child
        // has already exited.
        match *status {
            NotWaiting(pid) => child_pid = pid,
            Waiting => return Ok(None),
            Exited(exit_status) => return Ok(Some(exit_status)),
        };

        // No one is waiting on the child. Check to see if it's already exited.
        // If it has, put ourselves in the Exited state. (There can't be any
        // other waiters to signal, because the state was NotWaiting when we
        // started, and we're still holding the status lock.)
        let maybe_status = waitpid_nohang(child_pid)?;
        if let Some(exit_status) = maybe_status {
            *status = Exited(exit_status)
        }
        Ok(maybe_status)
    }

    /// Send a kill signal to the child, wait for it to exit, and return its
    /// exit status. This waits on the child to exit completely, to avoid
    /// leaving a zombie process on Unix.
    ///
    /// Because this waits, it's possible for this function to hang, if it fails
    /// to kill the child. That usually means that the child is blocked in
    /// kernel mode, for example on a FUSE filesystem call that is not
    /// responding. Callers that want to handle that situation somehow should
    /// either call `kill` in a background thread or use a different
    /// implementation that does not wait (though not waiting risks leaving a
    /// zombie process and leaking system resources).
    pub fn kill(&self) -> io::Result<ExitStatus> {
        let status = self.status_lock.lock().unwrap();
        if let Exited(exit_status) = *status {
            return Ok(exit_status);
        }
        // The child is still running. Kill it.
        self.child.lock().unwrap().kill()?;
        // Now clean it up, to avoid leaving a zombie on Unix. Drop the
        // status lock first, because wait() will retake it.
        drop(status);
        self.wait()
    }
}

enum ChildStatus {
    NotWaiting(u32),
    Waiting,
    Exited(ExitStatus),
}

use ChildStatus::*;

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
        // We were interrupted. Loop and retry.
    }
}

// This reaps the child if it's already exited, but doesn't block otherwise.
// There's an unstable Child::try_wait() function in libstd right now, and when
// that stabilizes we can probably delete this.
fn waitpid_nohang(pid: u32) -> io::Result<Option<ExitStatus>> {
    let mut status = 0;
    let waitpid_ret = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
    if waitpid_ret < 0 {
        // EINTR is not possible with WNOHANG, so no need to retry.
        Err(io::Error::last_os_error())
    } else if waitpid_ret == 0 {
        Ok(None)
    } else {
        use std::os::unix::process::ExitStatusExt;
        Ok(Some(ExitStatus::from_raw(status)))
    }
}

#[cfg(test)]
mod tests {
    use std;
    use std::process::Command;
    use super::*;

    #[test]
    fn test_wait() {
        let child = SharedChild::new(Command::new("true").spawn().unwrap());
        let status = child.wait().unwrap();
        assert_eq!(status.code().unwrap(), 0);
    }

    #[test]
    fn test_try_wait() {
        // This is a hack to check that try_wait will clean up a child that has
        // already exited. 100 milliseconds is "probably enough time". We could
        // try to do something fancy like blocking on pipes to see when the
        // child exits, but that might actually be less reliable, depending on
        // the order in which the OS chooses to do things.
        let child = SharedChild::new(Command::new("sleep").arg("0.1").spawn().unwrap());
        // Check immediately, and make sure the child hasn't exited yet.
        let maybe_status = child.try_wait().unwrap();
        assert_eq!(maybe_status, None);
        // Then sleep for a while and check again, after the child is supposed
        // to have exited.
        std::thread::sleep(std::time::Duration::from_millis(200));
        let maybe_status = child.try_wait().unwrap();
        assert!(maybe_status.is_some());
    }

    #[test]
    fn test_kill() {
        let child = SharedChild::new(Command::new("sleep").arg("1000").spawn().unwrap());
        // Check immediately, and make sure the child hasn't exited yet.
        let maybe_status = child.try_wait().unwrap();
        assert_eq!(maybe_status, None);
        // Now kill the child.
        child.kill().unwrap();
    }
}
