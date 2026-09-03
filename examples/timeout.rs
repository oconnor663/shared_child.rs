use shared_child::SharedChild;
use std::io;
use std::process::{Command, ExitStatus};
use std::time::Duration;

pub fn python_cmd(code: &str) -> Command {
    let mut cmd = if cfg!(windows) {
        // "Using Python on Windows...The recommended command for launching Python is `python`..."
        // https://docs.python.org/3/using/windows.html
        Command::new("python")
    } else {
        Command::new("python3")
    };
    cmd.arg("-c");
    cmd.arg(code);
    cmd
}

fn main() -> io::Result<()> {
    let mut cmd = python_cmd("import time; time.sleep(10)");
    let timeout = Duration::from_secs(5);
    let child = SharedChild::spawn(&mut cmd)?;
    let maybe_status: Option<ExitStatus> = child.wait_timeout(timeout)?;
    dbg!(maybe_status);
    Ok(())
}
