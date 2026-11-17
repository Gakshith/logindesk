//! Opaque 128-bit ids, shown as 32 lowercase hex chars (contract §3).

use std::fmt;
use std::str::FromStr;

/// Error parsing an id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadId;

impl fmt::Display for BadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a 32-char hex id")
    }
}

impl std::error::Error for BadId {}

fn random16() -> [u8; 16] {
    let mut b = [0u8; 16];
    // The OS RNG failing is unrecoverable for a security tool.
    #[allow(clippy::expect_used)]
    getrandom::fill(&mut b).expect("OS random number generator unavailable");
    b
}

macro_rules! id_type {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; 16]);

        impl $name {
            /// A fresh random id.
            pub fn random() -> Self {
                Self(random16())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for b in self.0 {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({self})", stringify!($name))
            }
        }

        impl FromStr for $name {
            type Err = BadId;
            fn from_str(s: &str) -> Result<Self, BadId> {
                let s = s.as_bytes();
                if s.len() != 32 {
                    return Err(BadId);
                }
                let mut out = [0u8; 16];
                for (i, pair) in s.chunks(2).enumerate() {
                    let hi = (pair[0] as char).to_digit(16).ok_or(BadId)?;
                    let lo = (pair[1] as char).to_digit(16).ok_or(BadId)?;
                    if pair.iter().any(u8::is_ascii_uppercase) {
                        return Err(BadId);
                    }
                    out[i] = (hi * 16 + lo) as u8;
                }
                Ok(Self(out))
            }
        }
    };
}

id_type!(
    /// A live browser session the broker holds for an agent.
    SessionId
);
id_type!(
    /// A pending approval the caller can wait on.
    Handle
);
id_type!(
    /// The public id of a login record.
    AccountId
);
id_type!(
    /// A paired MCP client.
    ClientId
);
id_type!(
    /// One approval request.
    RequestId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let a = SessionId::random();
        let s = a.to_string();
        assert_eq!(s.len(), 32);
        assert_eq!(s.parse::<SessionId>(), Ok(a));
        assert_ne!(SessionId::random(), a);
    }

    #[test]
    fn rejects_bad() {
        assert!("abc".parse::<Handle>().is_err());
        assert!("zz".repeat(16).parse::<Handle>().is_err());
        assert!("AB".repeat(16).parse::<Handle>().is_err());
    }
}
