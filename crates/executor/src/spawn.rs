//! Launch Chrome with `--remote-debugging-pipe`: Chrome reads CDP from fd 3 and writes to fd 4.
//! No TCP port is opened, so no other local process can drive the browser.

use std::io::{self, PipeReader, PipeWriter};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};

/// Spawn `cmd` with a fresh pipe pair on fds 3 (to Chrome) and 4 (from Chrome).
pub fn spawn_with_pipe(mut cmd: Command) -> io::Result<(Child, PipeWriter, PipeReader)> {
    let (to_chrome_r, to_chrome_w) = io::pipe()?;
    let (from_chrome_r, from_chrome_w) = io::pipe()?;
    let (a, b) = (to_chrome_r.as_raw_fd(), from_chrome_w.as_raw_fd());
    // SAFETY: the closure runs in the forked child before exec and only calls
    // async-signal-safe fcntl/dup2. Both ends are first moved above fd 10 so that
    // dup2 onto 3/4 cannot clobber one another; dup2 clears CLOEXEC on 3 and 4.
    unsafe {
        cmd.pre_exec(move || {
            let a2 = libc::fcntl(a, libc::F_DUPFD, 10);
            let b2 = libc::fcntl(b, libc::F_DUPFD, 10);
            if a2 < 0 || b2 < 0 || libc::dup2(a2, 3) < 0 || libc::dup2(b2, 4) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn()?;
    drop(to_chrome_r);
    drop(from_chrome_w);
    Ok((child, to_chrome_w, from_chrome_r))
}
