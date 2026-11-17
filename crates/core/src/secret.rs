//! [`Secret<T>`]: a value that must never reach a log, an error, an MCP
//! result or the calling agent.
//!
//! Guarantees:
//! - `Debug` and `Display` print [`REDACTED`], never the value.
//! - No `Serialize` (this crate does not depend on serde), no `Clone`, no
//!   `PartialEq`, no `Deref`. Reading the value takes an explicit
//!   [`Secret::expose`] call, which is easy to grep for in review.
//! - The value lives on the heap and is zeroized when the `Secret` drops.
//!   Moving a `Secret` moves only the pointer, so no stray copies are left
//!   behind by moves. A copy made before [`Secret::new`] (or by the caller
//!   after `expose`) is the caller's responsibility.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// The text printed in place of any secret value.
pub const REDACTED: &str = "[REDACTED]";

/// A secret value. See the [module docs](self) for what it guarantees.
pub struct Secret<T: Zeroize>(Box<T>);

/// The common case: a secret string (password, OTP, API key).
pub type SecretString = Secret<String>;

impl<T: Zeroize> Secret<T> {
    /// Wraps `value`. The value is moved to the heap and zeroized on drop.
    pub fn new(value: T) -> Self {
        Self(Box::new(value))
    }

    /// Borrows the secret value. Every call site is a place a secret is
    /// used, so keep them few and inside the daemon.
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// Marker: `Drop` above zeroizes the value.
impl<T: Zeroize> ZeroizeOnDrop for Secret<T> {}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T: Zeroize> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::*;

    // Canary values that are easy to spot and never real.
    const CANARIES: &[&str] = &[
        "CANARY-hunter2-7f3a",
        "p@ss w0rd with spaces",
        "]\"{}[REDACTED-not-really]",
        "unicodé-密码-🔑",
        "x",
    ];

    #[test]
    fn debug_never_contains_the_value() {
        for &value in CANARIES {
            let secret = SecretString::new(value.to_owned());
            for out in [format!("{secret:?}"), format!("{secret:#?}")] {
                assert_eq!(out, REDACTED);
                assert!(!out.contains(value), "Debug leaked {value:?}");
            }
        }
    }

    #[test]
    fn display_never_contains_the_value() {
        for &value in CANARIES {
            let secret = SecretString::new(value.to_owned());
            let out = format!("{secret}");
            assert_eq!(out, REDACTED);
            assert!(!out.contains(value), "Display leaked {value:?}");
        }
    }

    #[test]
    fn debug_of_a_containing_struct_never_contains_the_value() {
        #[derive(Debug)]
        #[allow(dead_code)] // fields are read only through Debug
        struct Login {
            site: &'static str,
            password: SecretString,
            otp: Option<Secret<Vec<u8>>>,
        }
        let value = "CANARY-nested-91c2";
        let login = Login {
            site: "example.com",
            password: SecretString::new(value.to_owned()),
            otp: Some(Secret::new(b"123456".to_vec())),
        };
        let out = format!("{login:?} {login:#?}");
        assert!(!out.contains(value));
        assert!(!out.contains("123456"));
        assert!(!out.contains("49, 50, 51")); // the OTP bytes as a list
        assert!(out.contains("example.com"));
    }

    #[test]
    fn secret_is_zeroize_on_drop() {
        fn assert_zod<T: ZeroizeOnDrop>() {}
        assert_zod::<SecretString>();
        assert_zod::<Secret<Vec<u8>>>();
    }

    #[test]
    fn expose_returns_the_value() {
        let secret = SecretString::from("CANARY-expose".to_owned());
        assert_eq!(secret.expose(), "CANARY-expose");
    }

    /// A value that records whether it was zeroized.
    struct Probe(Rc<Cell<bool>>);

    impl Zeroize for Probe {
        fn zeroize(&mut self) {
            self.0.set(true);
        }
    }

    #[test]
    fn value_is_zeroized_on_drop() {
        let zeroized = Rc::new(Cell::new(false));
        let secret = Secret::new(Probe(Rc::clone(&zeroized)));
        assert!(!zeroized.get());
        drop(secret);
        assert!(zeroized.get(), "Secret did not zeroize its value on drop");
    }

    #[test]
    fn string_zeroize_clears_the_contents() {
        // Documents what `Zeroize for String` does to the value Secret holds.
        let mut s = String::from("CANARY-zero");
        s.zeroize();
        assert!(s.is_empty());
    }
}
