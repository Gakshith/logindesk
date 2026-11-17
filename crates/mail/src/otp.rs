//! Find a one-time code (or a sign-in link) in one decoded message. Rules: docs/mail.md.

use logindesk_policy::registrable_domain;
use zeroize::Zeroizing;

use crate::mime::{Parsed, html_hrefs, html_to_text};

/// What one message holds.
pub enum Found {
    Code(Zeroizing<String>),
    Link(Zeroizing<String>),
    Ambiguous,
    Nothing,
}

/// A keyword may sit this many chars before a code...
const BEFORE: usize = 120;
/// ...or this many after it.
const AFTER: usize = 60;

/// Lowercase words that mark a code. `true` = must stand alone (not inside a longer word).
const KEYWORDS: &[(&str, bool)] = &[
    ("code", false),
    ("verification", false),
    ("verify", false),
    ("one-time", false),
    ("one time", false),
    ("otp", true),
    ("passcode", false),
    ("sign-in", false),
    ("sign in", false),
    ("log-in", false),
    ("log in", false),
    ("login", false),
    ("2fa", true),
    ("pin", true),
    ("security", false),
    // Non-English. German/Dutch/French "code" is covered above (Bestätigungscode, Anmeldecode).
    ("código", false),
    ("codigo", false),
    ("codice", false),
    ("kod", true),
    ("код", false),
    ("コード", false),
    ("验证码", false),
    ("驗證碼", false),
    ("인증", false),
];

/// Path words that make an on-site https link a sign-in link.
const LINK_WORDS: &[&str] = &["verify", "confirm", "magic", "login", "token"];

pub fn find(p: &Parsed, site: &str) -> Found {
    let body_text: Zeroizing<String> = match (&p.plain, &p.html) {
        (Some(t), _) => Zeroizing::new(t.to_string()),
        (None, Some(h)) => html_to_text(h),
        (None, None) => Zeroizing::new(String::new()),
    };
    let mut text = Zeroizing::new(String::with_capacity(p.subject.len() + body_text.len() + 1));
    text.push_str(&p.subject);
    text.push('\n');
    text.push_str(&body_text);

    let codes = codes_in(&text);
    match codes.len() {
        1 => {
            let mut codes = codes;
            if let Some(c) = codes.pop() {
                return Found::Code(c);
            }
        }
        0 => {}
        _ => return Found::Ambiguous,
    }

    let mut links: Vec<Zeroizing<String>> = Vec::new();
    // Links from the visible text plus every href of the HTML part (button links often only
    // live in the href).
    let hrefs = p.html.as_deref().map(|h| html_hrefs(h)).unwrap_or_default();
    for u in urls_in(&text).into_iter().chain(hrefs) {
        if sign_in_link(&u, site) {
            push_unique(&mut links, u);
        }
    }
    match links.len() {
        0 => Found::Nothing,
        1 => links.pop().map_or(Found::Nothing, Found::Link),
        _ => Found::Ambiguous,
    }
}

/// `http(s)://...` runs in plain text.
fn urls_in(text: &str) -> Vec<Zeroizing<String>> {
    let lower = Zeroizing::new(text.to_ascii_lowercase());
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(p) = lower[from..].find("http") {
        let start = from + p;
        let rest = &lower[start..];
        if !(rest.starts_with("https://") || rest.starts_with("http://")) {
            from = start + 4;
            continue;
        }
        let end = url_end(&text[start..]) + start;
        let u = text[start..end].trim_end_matches(['.', ',', ';', ':', ')', '!', '?', ']']);
        out.push(Zeroizing::new(u.to_string()));
        from = end.max(start + 4);
    }
    out
}

fn push_unique(v: &mut Vec<Zeroizing<String>>, x: Zeroizing<String>) {
    if !v.contains(&x) {
        v.push(x);
    }
}

fn url_end(s: &str) -> usize {
    s.find(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '"' | '\'' | '`'))
        .unwrap_or(s.len())
}

/// https on `site`, with a sign-in word in the path. Plain http is accepted only for
/// `*.localhost` (RFC 6761 loopback, the test bed), never for a real site.
fn sign_in_link(u: &str, site: &str) -> bool {
    let Ok(url) = url::Url::parse(u) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    let scheme_ok = match url.scheme() {
        "https" => true,
        "http" => host.ends_with(".localhost"),
        _ => false,
    };
    if !scheme_ok || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    if registrable_domain(host).as_deref() != Some(site) {
        return false;
    }
    let path = url.path().to_ascii_lowercase();
    LINK_WORDS.iter().any(|w| path.contains(w))
}

/// Replace every URL with spaces of the same char count, so digits inside links are never codes
/// and positions stay comparable.
fn blank_urls(text: &str) -> Vec<char> {
    let mut chars: Vec<char> = text.chars().collect();
    let lower: Vec<char> = chars
        .iter()
        .map(|c| c.to_lowercase().next().unwrap_or(*c))
        .collect();
    let mut i = 0;
    while i < lower.len() {
        let starts = |pat: &str| {
            pat.chars()
                .enumerate()
                .all(|(k, pc)| lower.get(i + k) == Some(&pc))
        };
        let skip = if starts("https://") {
            8
        } else if starts("http://") {
            7
        } else if starts("www.") {
            4
        } else {
            0
        };
        if skip > 0 {
            let mut j = i;
            while j < chars.len()
                && !chars[j].is_whitespace()
                && !matches!(chars[j], '<' | '>' | '"' | '\'')
            {
                chars[j] = ' ';
                j += 1;
            }
            i = j;
        } else {
            i += 1;
        }
    }
    chars
}

/// Keyword spans `(start, end)` in char positions.
fn keyword_spans(lower: &[char]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    for (kw, alone) in KEYWORDS {
        let k: Vec<char> = kw.chars().collect();
        if k.len() > lower.len() {
            continue;
        }
        for i in 0..=lower.len() - k.len() {
            if lower[i..i + k.len()] != k[..] {
                continue;
            }
            if *alone {
                let before = i.checked_sub(1).and_then(|b| lower.get(b));
                let after = lower.get(i + k.len());
                if before.is_some_and(|c| c.is_alphanumeric())
                    || after.is_some_and(|c| c.is_alphanumeric())
                {
                    continue;
                }
            }
            spans.push((i, i + k.len()));
        }
    }
    spans
}

/// One alphanumeric run.
struct Tok {
    start: usize,
    end: usize,
    s: String,
}

fn tokens(chars: &[char]) -> Vec<Tok> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_alphanumeric() {
            let start = i;
            while i < chars.len() && chars[i].is_alphanumeric() {
                i += 1;
            }
            out.push(Tok {
                start,
                end: i,
                s: chars[start..i].iter().collect(),
            });
        } else {
            i += 1;
        }
    }
    out
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// The candidate shape alone: 4–8 digits, or 6–8 uppercase ASCII alnum with at least one digit
/// and one letter.
fn code_shaped(s: &str) -> bool {
    let n = s.len();
    if !s.is_ascii() {
        return false;
    }
    if is_digits(s) {
        return (4..=8).contains(&n);
    }
    (6..=8).contains(&n)
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        && s.bytes().any(|b| b.is_ascii_digit())
}

/// Numeric tokens that are part of a phone number, a date, an amount or a decimal.
fn numeric_noise(chars: &[char], toks: &[Tok]) -> Vec<bool> {
    let mut noise = vec![false; toks.len()];
    // Groups of short numeric tokens joined only by phone/date punctuation: 555-123-4567,
    // (555) 123 4567, 2026-11-16.
    let joiner = |a: &Tok, b: &Tok| {
        let gap = &chars[a.end..b.start];
        !gap.is_empty()
            && gap.len() <= 3
            && gap
                .iter()
                .all(|c| matches!(c, ' ' | '-' | '.' | '(' | ')' | '/' | '\u{a0}'))
    };
    let short_num = |t: &Tok| is_digits(&t.s) && (2..=4).contains(&t.s.len());
    let mut i = 0;
    while i < toks.len() {
        if !short_num(&toks[i]) {
            i += 1;
            continue;
        }
        let mut j = i;
        while j + 1 < toks.len() && short_num(&toks[j + 1]) && joiner(&toks[j], &toks[j + 1]) {
            j += 1;
        }
        if j - i + 1 >= 3 {
            noise[i..=j].iter_mut().for_each(|n| *n = true);
        }
        i = j + 1;
    }
    for (k, t) in toks.iter().enumerate() {
        if !is_digits(&t.s) {
            continue;
        }
        let prev = t.start.checked_sub(1).map(|p| chars[p]);
        let prev2 = t.start.checked_sub(2).map(|p| chars[p]);
        let next = chars.get(t.end).copied();
        let next2 = chars.get(t.end + 1).copied();
        // International phone prefix, currency, decimals and thousands separators.
        if matches!(prev, Some('+' | '$' | '€' | '£' | '¥' | '₹'))
            || (matches!(prev, Some('.' | ',')) && prev2.is_some_and(|c| c.is_ascii_digit()))
            || (matches!(next, Some('.' | ',')) && next2.is_some_and(|c| c.is_ascii_digit()))
            || matches!(next, Some('%'))
        {
            noise[k] = true;
        }
        // A year.
        if t.s.len() == 4 && (t.s.starts_with("19") || t.s.starts_with("20")) {
            noise[k] = true;
        }
    }
    noise
}

/// Distinct code candidates near a keyword.
fn codes_in(text: &str) -> Vec<Zeroizing<String>> {
    let chars = Zeroizing::new(blank_urls(text));
    let lower: Zeroizing<Vec<char>> = Zeroizing::new(
        chars
            .iter()
            .map(|c| c.to_lowercase().next().unwrap_or(*c))
            .collect(),
    );
    let spans = keyword_spans(&lower);
    let toks = tokens(&chars);
    let noise = numeric_noise(&chars, &toks);
    let mut out = Vec::new();
    for (t, is_noise) in toks.iter().zip(noise) {
        if is_noise || !code_shaped(&t.s) {
            continue;
        }
        let near = spans.iter().any(|&(ks, ke)| {
            (ke <= t.start && t.start - ke <= BEFORE) || (ks >= t.end && ks - t.end <= AFTER)
        });
        if near {
            push_unique(&mut out, Zeroizing::new(t.s.clone()));
        }
    }
    let mut toks = toks;
    toks.iter_mut()
        .for_each(|t| zeroize::Zeroize::zeroize(&mut t.s));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(t: &str) -> Vec<String> {
        codes_in(t).iter().map(|c| c.to_string()).collect()
    }

    #[test]
    fn shapes() {
        assert!(code_shaped("4829"));
        assert!(code_shaped("48291375"));
        assert!(!code_shaped("482"));
        assert!(!code_shaped("482913751"));
        assert!(code_shaped("AB12CD"));
        assert!(!code_shaped("ABCDEF"));
        assert!(!code_shaped("ab12cd"));
        assert!(!code_shaped("AB1"));
    }

    #[test]
    fn noise_is_skipped() {
        assert!(codes("Your code: call 555-123-4567 for help").is_empty());
        assert!(codes("Your code was sent on 2026-11-16").is_empty());
        assert!(codes("Code price $1234 or 12.50 today").is_empty());
        assert!(codes("Code © 2026 Example").is_empty());
        assert!(codes("code at https://x.example.com/v/482913 now").is_empty());
        assert_eq!(
            codes("Your code is 482913. It expires in 10 minutes."),
            ["482913"]
        );
        assert!(codes("482913 appears far away from any keyword").is_empty());
    }
}
