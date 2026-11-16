//! Sites the broker never signs up on: banks, government, health, payments and
//! email providers. A small static list plus suffix rules; deliberately blunt.

/// Registrable domains refused for signup.
const BLOCKED: &[&str] = &[
    // email providers / identity
    "gmail.com",
    "google.com",
    "outlook.com",
    "live.com",
    "hotmail.com",
    "microsoft.com",
    "yahoo.com",
    "icloud.com",
    "apple.com",
    "proton.me",
    "protonmail.com",
    "fastmail.com",
    "aol.com",
    "zoho.com",
    "gmx.com",
    "mail.com",
    // payments / money
    "paypal.com",
    "stripe.com",
    "venmo.com",
    "wise.com",
    "cash.app",
    "squareup.com",
    "coinbase.com",
    "binance.com",
    "kraken.com",
    "revolut.com",
    "klarna.com",
    "affirm.com",
    "zellepay.com",
    // banks
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "citi.com",
    "capitalone.com",
    "usbank.com",
    "pnc.com",
    "discover.com",
    "americanexpress.com",
    "schwab.com",
    "fidelity.com",
    "vanguard.com",
    "hsbc.com",
    "barclays.co.uk",
    "santander.com",
    "ally.com",
    "sofi.com",
    "chime.com",
    // health
    "healthcare.gov",
    "mychart.org",
    "kaiserpermanente.org",
    "cvs.com",
    "walgreens.com",
    "unitedhealthcare.com",
    "anthem.com",
    "cigna.com",
    "aetna.com",
    "zocdoc.com",
];

/// Suffixes refused for signup (government, military, banks).
const BLOCKED_SUFFIXES: &[&str] = &[
    ".gov", ".mil", ".gov.uk", ".gov.au", ".gc.ca", ".gov.in", ".bank",
];

/// True when the broker must refuse to sign up on `site` (a registrable domain).
pub fn signup_blocked(site: &str) -> bool {
    let s = site.to_ascii_lowercase();
    BLOCKED.contains(&s.as_str()) || BLOCKED_SUFFIXES.iter().any(|x| s.ends_with(x))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_and_allows() {
        for s in [
            "paypal.com",
            "chase.com",
            "irs.gov",
            "nhs.gov.uk",
            "gmail.com",
            "mychart.org",
        ] {
            assert!(signup_blocked(s), "{s}");
        }
        for s in [
            "example.com",
            "example.localhost",
            "github.com",
            "govtrack.us",
        ] {
            assert!(!signup_blocked(s), "{s}");
        }
    }
}
