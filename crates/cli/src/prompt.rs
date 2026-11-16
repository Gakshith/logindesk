//! Reading the vault password and secrets: from the terminal (hidden), or
//! from stdin lines with `--password-stdin`.

use std::io::BufRead;

use logindesk_core::SecretString;

/// The error when a password is needed and there is no terminal to ask on.
pub fn no_terminal() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::NotConnected,
        "needs a terminal for the vault password (or use --password-stdin)",
    )
}

#[derive(Debug)]
pub struct Prompter {
    from_stdin: bool,
}

impl Prompter {
    pub fn new(from_stdin: bool) -> Self {
        Self { from_stdin }
    }

    /// Reads one secret. The returned `String` is moved straight into a
    /// `SecretString`, which zeroizes it on drop.
    pub fn secret(&mut self, prompt: &str) -> std::io::Result<SecretString> {
        let mut s = if self.from_stdin {
            let mut line = String::new();
            if std::io::stdin().lock().read_line(&mut line)? == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "stdin closed before a password was read",
                ));
            }
            line
        } else {
            if std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tty")
                .is_err()
            {
                return Err(no_terminal());
            }
            rpassword::prompt_password(prompt).map_err(|e| {
                // ENXIO: the process has no controlling terminal.
                if e.raw_os_error() == Some(6) {
                    no_terminal()
                } else {
                    e
                }
            })?
        };
        // Strip the line ending in place (no reallocation, no copy).
        while s.ends_with(['\n', '\r']) {
            s.pop();
        }
        Ok(SecretString::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_terminal_says_what_to_do() {
        let e = no_terminal();
        assert!(e.to_string().contains("needs a terminal"));
        assert!(e.to_string().contains("--password-stdin"));
        assert!(!e.to_string().contains("os error"));
    }
}
