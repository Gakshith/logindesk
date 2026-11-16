//! Generated signup passwords. Honours a page's `passwordrules` attribute
//! (the WHATWG/Apple syntax: `minlength`, `maxlength`, `required`, `allowed`,
//! `max-consecutive`); otherwise 20 characters from upper, lower, digits and
//! symbols. Randomness from the OS (getrandom), uniform by rejection sampling.

use logindesk_core::SecretString;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGIT: &str = "0123456789";
/// Conservative symbols most sites accept.
const SPECIAL: &str = "!@#$%^&*-_=+?";
/// Default length.
pub const DEFAULT_LEN: usize = 20;
/// Hard bounds whatever a page asks.
const MIN_LEN: usize = 8;
const MAX_LEN: usize = 64;

/// Parsed `passwordrules`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rules {
    min: usize,
    max: usize,
    /// Each set must contribute at least one character.
    required: Vec<Vec<char>>,
    /// Characters allowed anywhere (union of allowed and required).
    allowed: Vec<char>,
    max_consecutive: Option<usize>,
}

impl Default for Rules {
    fn default() -> Self {
        let required: Vec<Vec<char>> = [LOWER, UPPER, DIGIT, SPECIAL]
            .iter()
            .map(|s| s.chars().collect())
            .collect();
        Self {
            min: DEFAULT_LEN,
            max: DEFAULT_LEN,
            allowed: required.concat(),
            required,
            max_consecutive: None,
        }
    }
}

fn class(name: &str) -> Option<Vec<char>> {
    let set: String = match name.trim() {
        "lower" => LOWER.into(),
        "upper" => UPPER.into(),
        "digit" => DIGIT.into(),
        // Our symbol set, not every printable symbol: sites that say "special" accept these.
        "special" => SPECIAL.into(),
        "ascii-printable" | "unicode" => [LOWER, UPPER, DIGIT, SPECIAL].concat(),
        s if s.starts_with('[') && s.ends_with(']') && s.len() > 2 => s[1..s.len() - 1]
            .chars()
            .filter(|c| c.is_ascii_graphic())
            .collect(),
        _ => return None,
    };
    Some(set.chars().collect())
}

impl Rules {
    /// Parse a `passwordrules` value. Unknown parts are ignored; an empty or
    /// useless result falls back to the default.
    pub fn parse(s: &str) -> Self {
        let (mut min, mut max) = (None, None);
        let mut required: Vec<Vec<char>> = Vec::new();
        let mut allowed: Vec<char> = Vec::new();
        let mut max_consecutive = None;
        for part in s.split(';') {
            let Some((k, v)) = part.split_once(':') else {
                continue;
            };
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
            match k.as_str() {
                "minlength" => min = v.parse::<usize>().ok(),
                "maxlength" => max = v.parse::<usize>().ok(),
                "max-consecutive" => max_consecutive = v.parse::<usize>().ok().filter(|n| *n > 0),
                "required" | "allowed" => {
                    // `required: upper, lower` means one of upper-or-lower.
                    let set: Vec<char> = v.split(',').filter_map(class).flatten().collect();
                    if set.is_empty() {
                        continue;
                    }
                    if k == "required" {
                        required.push(set.clone());
                    }
                    allowed.extend(set);
                }
                _ => {}
            }
        }
        let mut r = Self::default();
        if !allowed.is_empty() {
            allowed.sort_unstable();
            allowed.dedup();
            r.allowed = allowed;
            r.required = required;
        }
        let lo = min.unwrap_or(MIN_LEN).clamp(MIN_LEN, MAX_LEN);
        let hi = max.unwrap_or(MAX_LEN).clamp(lo, MAX_LEN);
        r.min = lo;
        r.max = hi;
        r.max_consecutive = max_consecutive;
        r
    }

    fn len(&self) -> usize {
        DEFAULT_LEN.clamp(self.min, self.max)
    }
}

/// Uniform index below `n` from the OS RNG.
fn below(n: usize) -> usize {
    debug_assert!(n > 0 && n <= 256);
    let zone = 256 - (256 % n);
    loop {
        let mut b = [0u8; 1];
        // The OS RNG failing is unrecoverable for a security tool.
        #[allow(clippy::expect_used)]
        getrandom::fill(&mut b).expect("OS random number generator unavailable");
        if (b[0] as usize) < zone {
            return b[0] as usize % n;
        }
    }
}

fn pick(set: &[char]) -> char {
    set[below(set.len().min(256))]
}

fn ok_consecutive(p: &[char], max: Option<usize>) -> bool {
    let Some(m) = max else { return true };
    let mut run = 1;
    for w in p.windows(2) {
        run = if w[0] == w[1] { run + 1 } else { 1 };
        if run > m {
            return false;
        }
    }
    true
}

/// Generate a password for `rules` (`None` = the default rules).
pub fn generate(rules: Option<&str>) -> SecretString {
    let r = rules.map(Rules::parse).unwrap_or_default();
    let n = r.len().max(r.required.len());
    loop {
        let mut p: Vec<char> = r.required.iter().map(|s| pick(s)).collect();
        while p.len() < n {
            p.push(pick(&r.allowed));
        }
        // Fisher-Yates, so required characters are not always first.
        for i in (1..p.len()).rev() {
            p.swap(i, below(i + 1));
        }
        if ok_consecutive(&p, r.max_consecutive) {
            return SecretString::new(p.into_iter().collect());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has(p: &str, set: &str) -> bool {
        p.chars().any(|c| set.contains(c))
    }

    #[test]
    fn default_is_20_from_four_classes() {
        for _ in 0..50 {
            let s = generate(None);
            let p = s.expose();
            assert_eq!(p.chars().count(), 20);
            assert!(
                has(p, LOWER) && has(p, UPPER) && has(p, DIGIT) && has(p, SPECIAL),
                "{p}"
            );
        }
        assert_ne!(generate(None).expose(), generate(None).expose());
    }

    #[test]
    fn honours_passwordrules() {
        let rules = "minlength: 8; maxlength: 12; required: digit; required: [-]; allowed: lower; max-consecutive: 2";
        for _ in 0..50 {
            let s = generate(Some(rules));
            let p = s.expose();
            let n = p.chars().count();
            assert!((8..=12).contains(&n), "{p}");
            assert!(has(p, DIGIT) && p.contains('-'), "{p}");
            assert!(
                p.chars()
                    .all(|c| LOWER.contains(c) || DIGIT.contains(c) || c == '-'),
                "{p}"
            );
            assert!(
                ok_consecutive(&p.chars().collect::<Vec<_>>(), Some(2)),
                "{p}"
            );
        }
        // Digits only, short.
        let s = generate(Some("required: digit; maxlength: 6"));
        assert!(s.expose().chars().all(|c| c.is_ascii_digit()));
        assert_eq!(s.expose().len(), 8, "never below the hard minimum");
        // Garbage falls back to the default.
        assert_eq!(generate(Some("nonsense")).expose().chars().count(), 20);
    }
}
