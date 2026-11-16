//! Reading the vault password and secrets: from the terminal (hidden), or
//! from stdin lines with `--password-stdin`.

use std::io::BufRead;

use logindesk_core::SecretString;

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
            rpassword::prompt_password(prompt)?
        };
        // Strip the line ending in place (no reallocation, no copy).
        while s.ends_with(['\n', '\r']) {
            s.pop();
        }
        Ok(SecretString::new(s))
    }
}
