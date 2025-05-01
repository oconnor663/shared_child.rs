//! A library for awaiting and killing child processes from multiple threads.
//!
//! - [Docs](https://docs.rs/shared_child)
//! - [Crate](https://crates.io/crates/shared_child)
//! - [Repo](https://github.com/oconnor663/shared_child.rs)
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
//! Compatibility note: The `libc` crate doesn't currently support `waitid` on
//! NetBSD or OpenBSD, or on older versions of OSX. There [might also
//! be](https://bugs.python.org/msg167016) some version of OSX where the
//! `waitid` function exists but is broken. We can add a "best effort"
//! workaround using `waitpid` for these platforms as we run into them. Please
//! [file an issue](https://github.com/oconnor663/shared_child.rs/issues/new) if
//! you hit this.
//!
//! # Example
//!
//! ```rust
//! use shared_child::SharedChild;
//! use std::process::Command;
//! use std::sync::Arc;
//!
//! // Spawn a child that will just sleep for a long time,
//! // and put it in an Arc to share between threads.
//! let mut command = Command::new("python");
//! command.arg("-c").arg("import time; time.sleep(1000000000)");
//! let shared_child = SharedChild::spawn(&mut command).unwrap();
//! let child_arc = Arc::new(shared_child);
//!
//! // On another thread, wait on the child process.
//! let child_arc_clone = child_arc.clone();
//! let thread = std::thread::spawn(move || {
//!     child_arc_clone.wait().unwrap()
//! });
//!
//! // While the other thread is waiting, kill the child process.
//! // This wouldn't be possible with e.g. Arc<Mutex<Child>> from
//! // the standard library, because the waiting thread would be
//! // holding the mutex.
//! child_arc.kill().unwrap();
//!
//! // Join the waiting thread and get the exit status.
//! let exit_status = thread.join().unwrap();
//! assert!(!exit_status.success());
//! ```

use std::io;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus};
use std::sync::{Condvar, Mutex};

mod sys;

// Publish the Unix-only SharedChildExt trait.
#[cfg(unix)]
pub mod unix;

#[derive(Debug)]
enum ChildState {
    NotWaiting,
    Waiting,
    // std::process::Child caches the exit status internally, and we could *almost* get away with
    // omitting the Exited state here and just calling Child::try_wait whenever we wanted it. But
    // the one place we definitely can't get away with that is send_signal, because we never want
    // reaping the child to race against a blocking call to waitid. (SharedChild::try_wait
    // short-circuits in the Waiting state, so it doesn't have this issue, but send_signal needs to
    // work in that state.)
    Exited(ExitStatus),
}

use crate::ChildState::{Exited, NotWaiting, Waiting};

#[derive(Debug)]
struct SharedChildInner {
    child: Child,
    state: ChildState,
}

impl SharedChildInner {
    fn new(child: Child) -> Self {
        Self {
            child,
            state: NotWaiting,
        }
    }

    // This is the only codepath in this crate that reaps the child process.
    fn try_wait_and_reap(&mut self) -> io::Result<Option<ExitStatus>> {
        // We never want reaping to race with other waiters.
        assert!(
            matches!(self.state, NotWaiting),
            "unexpected state {:?}",
            self.state,
        );
        // This is the standard Child::try_wait API. On Unix it calls waitpid with WNOHANG.
        if let Some(exit_status) = self.child.try_wait()? {
            self.state = Exited(exit_status);
            Ok(Some(exit_status))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug)]
pub struct SharedChild {
    inner: Mutex<SharedChildInner>,
    condvar: Condvar,
}

impl SharedChild {
    /// Spawn a new `SharedChild` from a
    /// [`std::process::Command`](https://doc.rust-lang.org/std/process/struct.Command.html).
    pub fn spawn(command: &mut Command) -> io::Result<Self> {
        Ok(SharedChild {
            inner: Mutex::new(SharedChildInner::new(command.spawn()?)),
            condvar: Condvar::new(),
        })
    }

    /// Construct a new `SharedChild` from an already spawned
    /// [`std::process::Child`](https://doc.rust-lang.org/std/process/struct.Child.html).
    ///
    /// This constructor needs to know whether `child` has already been waited on, and the only way
    /// to find that out is to call
    /// [`Child::try_wait`](https://doc.rust-lang.org/std/process/struct.Child.html#method.try_wait)
    /// internally. If the child process is currently a zombie, that call will clean it up as a
    /// side effect. The [`SharedChild::spawn`] constructor doesn't need to do this.
    pub fn new(child: Child) -> io::Result<Self> {
        // See the comment on the Exited variant above for more about why this is the way it is.
        let mut inner = SharedChildInner::new(child);
        inner.try_wait_and_reap()?;
        Ok(SharedChild {
            inner: Mutex::new(inner),
            condvar: Condvar::new(),
        })
    }

    /// Return the child process ID.
    pub fn id(&self) -> u32 {
        self.inner.lock().unwrap().child.id()
    }

    /// Wait for the child to exit, blocking the current thread, and return its
    /// exit status.
    pub fn wait(&self) -> io::Result<ExitStatus> {
        // Start by taking the inner lock, but note that we need to release it before doing a
        // blocking wait, or else .try_wait() and .kill() would block.
        let mut inner_guard = self.inner.lock().unwrap();
        loop {
            match inner_guard.state {
                NotWaiting => {
                    // Either no one is waiting on the child yet, or a previous
                    // waiter failed. That means we need to do it ourselves.
                    // Break out of this loop.
                    break;
                }
                Waiting => {
                    // Another thread is already waiting on the child. We'll
                    // block until it signal us on the condvar, then loop again.
                    // Spurious wakeups could bring us here multiple times
                    // though, see the Condvar docs.
                    inner_guard = self.condvar.wait(inner_guard).unwrap();
                }
                Exited(exit_status) => return Ok(exit_status),
            }
        }

        // We have the inner lock, and we're the thread responsible for waiting on the child. We're
        // about to release the lock and do a blocking, non-reaping wait. However, there's another
        // subtle race condition we need to worry about, apart from the kill/wait PID reuse race
        // that this crate is all about. Here's a possible order of events:
        //   1. The child process exits.
        //   2. Lots of time passes. Now any waiter will certainly see that the child has exited.
        //   3. One thread calls .wait(). It acquires the lock, sets the status to Waiting, and
        //      releases the lock, in preparation for attempting its blocking wait.
        //   4. Suddently, another thread swoops in and calls .try_wait(). That thread acquires the
        //      lock, sees the Waiting status, and returns None. ***THIS IS A BUG.***
        //   5. The first thread sees that the child has exited, reacquires the lock, and cleans
        //      up.
        // If the call to .try_wait() were racing against the child's actual exit, then we wouldn't
        // care what it returned. That would be an "honest" race, and it would be correct for the
        // result to be a coin flip. But that's not what happens in this situation. Here the child
        // has definitely exited, maybe seconds or minutes ago, and a single call to .try_wait()
        // would certainly have returned Some. It's only by racing against .wait() that this
        // situation could incorrectly report that the child hasn't exited.
        //
        // To fix this, .wait() must do a non-blocking wait (that is, actually check the status of
        // the child process) *before* releasing the lock. If that returns false, then the only
        // possible race is a race against the child itself, where again it's expected and fine for
        // the result to be a coin flip. Doing this before setting inner.state to Waiting
        // simplifies error handling. (try_wait_and_reap also asserts the NotWaiting state.)
        if let Some(exit_status) = inner_guard.try_wait_and_reap()? {
            return Ok(exit_status);
        }

        // We're still holding the inner lock, and the child process has not yet exited. Release
        // the lock so that we can do a blocking wait. Once we enter the Waiting state, we must get
        // out of that state before returning (or else we'll deadlock other callers), so we don't
        // do any short-circuiting or ? error handling in this "critical section".
        inner_guard.state = Waiting;
        let handle = sys::get_handle(&inner_guard.child);
        drop(inner_guard);

        // Block until the child exits without reaping it. (On Unix, that means we need to call
        // libc::waitid with the WNOWAIT flag. On Windows waiting never reaps.) That makes it safe
        // for another thread to kill() while we're here, without racing against some process
        // reusing the child's PID. Having only one thread in this section is important, because
        // POSIX doesn't guarantee much about what happens when multiple threads wait on a child at
        // the same time: http://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html#tag_15_13
        // It's probably fine to have multiple waiters if they're all WNOWAIT, but it's definitely
        // not fine to have multiple waiters if one of them is a reaper. See also:
        // https://gist.github.com/oconnor663/73266d2e552c3d9ef6e1e9259c58bfab
        //
        // Again, we can't short-circuit if this fails.
        let noreap_result = sys::wait_without_reaping(handle);

        // No matter what happened, retake the lock, leave the Waiting state, and signal the
        // condvar. (Again note that try_wait_and_reap asserts the NotWaiting state.)
        inner_guard = self.inner.lock().unwrap();
        inner_guard.state = NotWaiting;
        self.condvar.notify_all();

        // Now the "critical section" is over, and it's safe to short-circuit again. If
        // wait_without_reaping succeeded (and fwiw I'm not aware of any natural case where it
        // could fail), reap the child and update the state to Exited. Use Child::try_wait instead
        // of Child::wait to do this, because if we somehow find out (to our horror) that the child
        // hasn't *actually* exited, I'd rather panic than block forever holding the inner lock.
        noreap_result?;
        Ok(inner_guard
            .try_wait_and_reap()?
            .expect("the child should have exited"))
    }

    /// Return the child's exit status if it has already exited. If the child is
    /// still running, return `Ok(None)`.
    pub fn try_wait(&self) -> io::Result<Option<ExitStatus>> {
        // NOTE: Taking this lock will not block, because wait() doesn't hold it while blocking.
        let mut inner_guard = self.inner.lock().unwrap();

        // Unlike wait() above, we don't loop on the Condvar here. If the status is Waiting or
        // Exited, we return immediately. However, if the status is NotWaiting, we'll do a
        // non-blocking wait below, which reaps the child if it has already exited.
        match inner_guard.state {
            // If there are no blocking waiters, fall through.
            NotWaiting => {}

            // If another thread is already doing a blocking .wait(), short circuit without
            // checking the child. It could be ok to have multiple threads calling waitid at the
            // same time if they all used WNOWAIT. (We don't actually do that, but we could.)
            // However, it's *not* ok to let one thread reap the child (i.e. inner.child.try_wait()
            // below) while other threads are waiting, because some of the waiters will randomly
            // get "No child processes" errors depending on the kernel's order of operations. So we
            // don't want to fall through in this case. We rely on the waiting thread to do an
            // initial non-blocking wait before releasing the inner lock, to avoid a race in the
            // case where the child exited long ago. See the comments in .wait() above.
            Waiting => return Ok(None),

            Exited(exit_status) => return Ok(Some(exit_status)),
        };

        // No one is waiting on the child. Check to see if it's already exited. If it has, reap it
        // and put ourselves in the Exited state. There can't be any other waiters to signal,
        // because the state was NotWaiting when we started, and we're still holding the lock.
        inner_guard.try_wait_and_reap()
    }

    /// Send a kill signal to the child. On Unix this sends SIGKILL, and you
    /// should call `wait` afterwards to avoid leaving a zombie. If the process
    /// has already been waited on, this returns `Ok(())` and does nothing.
    pub fn kill(&self) -> io::Result<()> {
        // The reason we can do this, but the standard library can't, is that our SharedChild::wait
        // function uses the newer (i.e. only 20 years old) libc::waitid with the WNOHANG flag,
        // which lets it wait for the child to exit without reaping it. The actual reaping happens
        // after SharedChild::wait re-acquires the inner lock, which is the same lock we take here,
        // preventing the PID reuse race.
        //
        // Taking this lock won't block, because wait() doesn't hold it while blocking. Also we
        // always reap the child process via Child::try_wait, so this is a no-op after the child
        // process is reaped.
        self.inner.lock().unwrap().child.kill()
    }

    /// Consume the `SharedChild` and return the
    /// [`std::process::Child`](https://doc.rust-lang.org/std/process/struct.Child.html)
    /// it contains.
    ///
    /// We never reap the child process except by calling `Child::try_wait` on it, so the child
    /// object's inner state is correct, even if it was waited on while it was shared.
    pub fn into_inner(self) -> Child {
        self.inner.into_inner().unwrap().child
    }

    /// Take the child's
    /// [`stdin`](https://doc.rust-lang.org/std/process/struct.Child.html#structfield.stdin)
    /// handle, if any.
    ///
    /// This will only return `Some` the first time it's called, and then only if the `Command`
    /// that created the child was configured with `.stdin(Stdio::piped())`.
    pub fn take_stdin(&self) -> Option<ChildStdin> {
        self.inner.lock().unwrap().child.stdin.take()
    }

    /// Take the child's
    /// [`stdout`](https://doc.rust-lang.org/std/process/struct.Child.html#structfield.stdout)
    /// handle, if any.
    ///
    /// This will only return `Some` the first time it's called, and then only if the `Command`
    /// that created the child was configured with `.stdout(Stdio::piped())`.
    pub fn take_stdout(&self) -> Option<ChildStdout> {
        self.inner.lock().unwrap().child.stdout.take()
    }

    /// Take the child's
    /// [`stderr`](https://doc.rust-lang.org/std/process/struct.Child.html#structfield.stderr)
    /// handle, if any.
    ///
    /// This will only return `Some` the first time it's called, and then only if the `Command`
    /// that created the child was configured with `.stderr(Stdio::piped())`.
    pub fn take_stderr(&self) -> Option<ChildStderr> {
        self.inner.lock().unwrap().child.stderr.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::process::{Command, Stdio};
    use std::sync::Arc;

    // Python isn't available on some Unix platforms, e.g. Android, so we need this instead.
    #[cfg(unix)]
    pub fn true_cmd() -> Command {
        Command::new("true")
    }

    #[cfg(not(unix))]
    pub fn true_cmd() -> Command {
        let mut cmd = Command::new("python");
        cmd.arg("-c").arg("");
        cmd
    }

    // Python isn't available on some Unix platforms, e.g. Android, so we need this instead.
    #[cfg(unix)]
    pub fn sleep_forever_cmd() -> Command {
        let mut cmd = Command::new("sleep");
        cmd.arg("1000000");
        cmd
    }

    #[cfg(not(unix))]
    pub fn sleep_forever_cmd() -> Command {
        let mut cmd = Command::new("python");
        cmd.arg("-c").arg("import time; time.sleep(1000000)");
        cmd
    }

    // Python isn't available on some Unix platforms, e.g. Android, so we need this instead.
    #[cfg(unix)]
    pub fn cat_cmd() -> Command {
        Command::new("cat")
    }

    #[cfg(not(unix))]
    pub fn cat_cmd() -> Command {
        let mut cmd = Command::new("python");
        cmd.arg("-c").arg("");
        cmd
    }

    #[test]
    fn test_wait() {
        let child = SharedChild::spawn(&mut true_cmd()).unwrap();
        // Test the id() function while we're at it.
        let id = child.id();
        assert!(id > 0);
        let status = child.wait().unwrap();
        assert_eq!(status.code().unwrap(), 0);
    }

    #[test]
    fn test_kill() {
        let child = SharedChild::spawn(&mut sleep_forever_cmd()).unwrap();
        child.kill().unwrap();
        let status = child.wait().unwrap();
        assert!(!status.success());
    }

    #[test]
    fn test_try_wait() {
        let child = SharedChild::spawn(&mut sleep_forever_cmd()).unwrap();
        let maybe_status = child.try_wait().unwrap();
        assert_eq!(maybe_status, None);
        child.kill().unwrap();
        // The child will handle that signal asynchronously, so we check it
        // repeatedly in a busy loop.
        let mut maybe_status = None;
        while let None = maybe_status {
            maybe_status = child.try_wait().unwrap();
        }
        assert!(maybe_status.is_some());
        assert!(!maybe_status.unwrap().success());
    }

    #[test]
    fn test_many_waiters() {
        let child = Arc::new(SharedChild::spawn(&mut sleep_forever_cmd()).unwrap());
        let mut threads = Vec::new();
        for _ in 0..10 {
            let clone = child.clone();
            threads.push(std::thread::spawn(move || clone.wait()));
        }
        child.kill().unwrap();
        for thread in threads {
            thread.join().unwrap().unwrap();
        }
    }

    #[test]
    fn test_waitid_after_exit_doesnt_hang() {
        // There are ominous reports (https://bugs.python.org/issue10812) of a
        // broken waitid implementation on OSX, which might hang forever if it
        // tries to wait on a child that's already exited.
        let child = true_cmd().spawn().unwrap();
        sys::wait_without_reaping(sys::get_handle(&child)).unwrap();
        // At this point the child has definitely exited. Wait again to test
        // that a second wait doesn't block.
        sys::wait_without_reaping(sys::get_handle(&child)).unwrap();
    }

    #[test]
    fn test_into_inner_before_wait() {
        let shared_child = SharedChild::spawn(&mut sleep_forever_cmd()).unwrap();
        let mut child = shared_child.into_inner();
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn test_into_inner_after_wait() {
        // This makes sure the child's inner state is valid. If we used waitpid
        // on the side, the inner child would try to wait again and cause an
        // error.
        let shared_child = SharedChild::spawn(&mut sleep_forever_cmd()).unwrap();
        shared_child.kill().unwrap();
        shared_child.wait().unwrap();
        let mut child = shared_child.into_inner();
        // Wait should succeed. (Note that we also used to test that
        // child.kill() failed here, but its behavior changed in Rust 1.72.)
        child.wait().unwrap();
    }

    #[test]
    fn test_new() -> Result<(), Box<dyn Error>> {
        // Spawn a short-lived child.
        let mut command = cat_cmd();
        command.stdin(Stdio::piped());
        command.stdout(Stdio::null());
        let mut child = command.spawn()?;
        let child_stdin = child.stdin.take().unwrap();

        // Construct a SharedChild from the Child, which has not yet been waited on. The child is
        // blocked on stdin, so we know it hasn't yet exited.
        let mut shared_child = SharedChild::new(child).unwrap();
        assert!(matches!(
            shared_child.inner.lock().unwrap().state,
            NotWaiting,
        ));

        // Now close the child's stdin. This will cause the child to exit.
        drop(child_stdin);

        // Construct more SharedChild objects from the same child, in a loop. Eventually one of
        // them will notice that the child has exited.
        loop {
            shared_child = SharedChild::new(shared_child.into_inner())?;
            if let Exited(status) = shared_child.inner.lock().unwrap().state {
                assert!(status.success());
                return Ok(());
            }
        }
    }

    #[test]
    fn test_takes() -> Result<(), Box<dyn Error>> {
        let mut command = true_cmd();
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        let shared_child = SharedChild::spawn(&mut command)?;

        assert!(shared_child.take_stdin().is_some());
        assert!(shared_child.take_stdout().is_some());
        assert!(shared_child.take_stderr().is_some());

        assert!(shared_child.take_stdin().is_none());
        assert!(shared_child.take_stdout().is_none());
        assert!(shared_child.take_stderr().is_none());

        shared_child.wait()?;
        Ok(())
    }

    #[test]
    fn test_wait_try_wait_race() -> Result<(), Box<dyn Error>> {
        // Make sure that .wait() and .try_wait() can't race against each other. The scenario we're
        // worried about is:
        //   1. wait() takes the child lock, set the state to Waiting, and releases the child lock.
        //   2. try_wait swoops in, takes the child lock, sees the Waiting state, and returns
        //      Ok(None).
        //   3. wait() resumes, actually calls waitit(), observes the child has exited, retakes the
        //      child lock, reaps the child, and sets the state to Exited.
        // A race like this could cause .try_wait() to report that the child hasn't exited, even if
        // in fact the child exited long ago. A subsequent call to .try_wait() would almost
        // certainly report Ok(Some(_)), but the first call is still a bug. The way to prevent the
        // bug is by either [a] making .try_wait() call waitid() even it the state is Waiting or
        // [b] making .wait() do a non-blocking call to waitid() before releasing the child lock.
        // (Remember that we can't hold the child lock while blocking.)
        //
        // This was a failing test when I first committed it. Most of the time it would fail after
        // a few hundred iterations, but sometimes it took thousands. Default to one second so that
        // the tests don't take too long, but use an env var to configure a really big run in CI.
        use std::time::{Duration, Instant};
        let mut test_duration_secs: u64 = 1;
        if let Ok(test_duration_secs_str) = std::env::var("SHARED_CHILD_RACE_TEST_SECONDS") {
            dbg!(&test_duration_secs_str);
            test_duration_secs = test_duration_secs_str.parse().expect("invalid u64");
        }
        let test_duration = Duration::from_secs(test_duration_secs);
        let test_start = Instant::now();
        let mut iterations = 1u64;
        loop {
            // Start a child that will exit immediately.
            let child = SharedChild::spawn(&mut true_cmd())?;
            // Wait for the child to exit, without updating the SharedChild state.
            let handle = sys::get_handle(&child.inner.lock().unwrap().child);
            sys::wait_without_reaping(handle)?;
            // Spawn two threads, one to wait() and one to try_wait(). It should be impossible for the
            // try_wait thread to return Ok(None) at this point. However, we want to make sure there's
            // no race condition between them, where the wait() thread has said it's waiting and
            // released the child lock but hasn't yet actually waited.
            let barrier = std::sync::Barrier::new(2);
            let try_wait_ret = std::thread::scope(|scope| {
                scope.spawn(|| {
                    barrier.wait();
                    child.wait().unwrap();
                });
                scope
                    .spawn(|| {
                        barrier.wait();
                        child.try_wait().unwrap()
                    })
                    .join()
                    .unwrap()
            });
            let test_time_so_far = Instant::now().saturating_duration_since(test_start);
            assert!(
                try_wait_ret.is_some(),
                "encountered the race condition after {:?} ({} iterations)",
                test_time_so_far,
                iterations,
            );
            iterations += 1;

            // If we've met the target test duration (1 sec by default), exit with success.
            // Otherwise keep looping and trying to provoke the race.
            if test_time_so_far >= test_duration {
                return Ok(());
            }
        }
    }
}
