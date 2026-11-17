//! Fixture data the fake site and the Gmail mock serve. Tests construct these themselves so they
//! know every value; wave 3 replaces the password/seed values with canary markers.

use rand::RngExt;

/// The site's own domain in mails and the Gmail mock.
pub const SITE_DOMAIN: &str = "example.localhost";

/// The values the fake site and the Gmail mock accept.
#[derive(Debug, Clone)]
pub struct Fixtures {
    /// Existing account that logs in with a password only.
    pub user_email: String,
    /// Existing account whose login also needs an emailed one-time code.
    pub otp_user_email: String,
    /// Password of both existing accounts.
    pub user_password: String,
    /// Raw TOTP seed (RFC 6238, SHA-1, 30 s, 6 digits) for the `/totp` page.
    pub totp_seed: Vec<u8>,
    /// Bearer token the Gmail mock accepts.
    pub gmail_token: String,
}

/// `len` random alphanumeric characters.
pub fn random_alnum(len: usize) -> String {
    let mut rng = rand::rng();
    (0..len)
        .map(|_| char::from(rng.sample(rand::distr::Alphanumeric)))
        .collect()
}

impl Fixtures {
    /// Fresh random values; the accounts are fixed addresses on [`SITE_DOMAIN`].
    pub fn random() -> Self {
        let mut seed = vec![0u8; 20];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
        Self {
            user_email: format!("alice@{SITE_DOMAIN}"),
            otp_user_email: format!("otp@{SITE_DOMAIN}"),
            user_password: format!("pw-{}", random_alnum(20)),
            totp_seed: seed,
            gmail_token: format!("ya29.mock-{}", random_alnum(32)),
        }
    }
}
