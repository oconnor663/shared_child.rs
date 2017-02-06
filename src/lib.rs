//! A library for awaiting and killing child processes from multiple threads.
//!
//! The
//! [`std::process::Child`](https://doc.rust-lang.org/std/process/struct.Child.html)
//! type in the standard library provides
//! [`wait`](https://doc.rust-lang.org/std/process/struct.Child.html#method.wait)
//! and
//! [`kill`](https://doc.rust-lang.org/std/process/struct.Child.html#method.kill)
//! methods that take `&mut self`, making it impossible to kill a child process
//! while another thread is waiting on it. That design works around a race
//! condition in Unix's `waitpid` function, where a PID might get reused as soon
//! as the wait returns, so a signal sent around the same time could
//! accidentally get delivered to the wrong process.
//!
//! However with the newer POSIX `waitid` function, we can wait on a child
//! without freeing its PID for reuse. That makes it safe to send signals
//! concurrently. Windows has actually always supported this, by preventing PID
//! reuse while there are still open handles to a child process. This library
//! wraps `std::process::Child` for concurrent use, backed by these APIs.
//!
//! - [Docs](https://docs.rs/shared_child)
//! - [Crate](https://crates.io/crates/shared_child)
//! - [Repo](https://github.com/oconnor663/shared_child.rs)

extern crate libc;

use std::io;
use std::process::{Command, Child, ExitStatus};
use std::sync::{Condvar, Mutex};

#[cfg(not(windows))]
#[path="unix.rs"]
mod sys;
#[cfg(windows)]
#[path="windows.rs"]
mod sys;

pub struct SharedChild {
    // This lock provides shared access to kill() and wait(), though sometimes
    // we use libc::waitpid() to reap the child instead. This is a *shared*
    // child, so we never hold onto this lock for a blocking wait.
    child: Mutex<Child>,
    id: u32,
    handle: sys::Handle,

    // Threads doing blocking waits will wait on this condvar, and the first
    // waiter will call libc::waitid(), to avoid racing against kill().
    status_lock: Mutex<ChildStatus>,
    status_condvar: Condvar,
}

impl SharedChild {
    /// Spawn a new `SharedChild` from a `std::process::Command`.
    pub fn spawn(command: &mut Command) -> io::Result<SharedChild> {
        let child = command.spawn()?;
        Ok(SharedChild {
            id: child.id(),
            handle: sys::get_handle(&child),
            child: Mutex::new(child),
            status_lock: Mutex::new(NotWaiting),
            status_condvar: Condvar::new(),
        })
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    /// Wait for the child to exit, blocking the current thread, and return its
    /// exit status.
    pub fn wait(&self) -> io::Result<ExitStatus> {
        let mut status = self.status_lock.lock().unwrap();
        loop {
            match *status {
                NotWaiting => {
                    // No one is waiting on the child yet. That means we need to
                    // do it ourselves. Break out of the loop.
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
        sys::wait_without_reaping(&self.handle)?;

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

        // Unlike wait() above, we don't loop on the Condvar here. If the status
        // is Waiting or Exited, we return immediately. However, if the status
        // is NotWaiting, we'll do a non-blocking wait below, in case the child
        // has already exited.
        match *status {
            NotWaiting => {}
            Waiting => return Ok(None),
            Exited(exit_status) => return Ok(Some(exit_status)),
        };

        // No one is waiting on the child. Check to see if it's already exited.
        // If it has, put ourselves in the Exited state. (There can't be any
        // other waiters to signal, because the state was NotWaiting when we
        // started, and we're still holding the status lock.)
        let maybe_status = sys::try_wait(&self.handle)?;
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
    NotWaiting,
    Waiting,
    Exited(ExitStatus),
}

use ChildStatus::*;

#[cfg(test)]
mod tests {
    use std;
    use std::process::Command;
    use super::*;

    #[test]
    fn test_wait() {
        let child = SharedChild::spawn(&mut Command::new("true")).unwrap();
        assert!(child.id() > 0);
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
        let child = SharedChild::spawn(Command::new("sleep").arg("0.1")).unwrap();
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
        let child = SharedChild::spawn(Command::new("sleep").arg("1000")).unwrap();
        // Check immediately, and make sure the child hasn't exited yet.
        let maybe_status = child.try_wait().unwrap();
        assert_eq!(maybe_status, None);
        // Now kill the child.
        child.kill().unwrap();
    }
}
