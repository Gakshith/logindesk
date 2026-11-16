//! Sender authentication from the receiving server's `Authentication-Results` header.
//!
//! Only the topmost `Authentication-Results` header counts: the receiving server prepends it,
//! so a sender cannot put one above it. When `authserv` is given (Gmail: `mx.google.com`), that
//! header must also carry that authserv-id, otherwise the message is rejected.
//!
//! Pass = `dmarc=pass` with `header.from` on the site, or `dkim=pass` with a signing domain
//! (`header.d` / `header.i`) on the site.

use logindesk_policy::registrable_domain;

use crate::mime::{parse_headers, split_head_body};

/// The receiving server says this message was signed by (or DMARC-aligned with) `site`.
pub fn dkim_aligned(raw: &[u8], site: &str, authserv: Option<&str>) -> bool {
    let raw = &raw[..raw.len().min(crate::mime::MAX_MESSAGE_BYTES)];
    let (head, _) = split_head_body(raw);
    let hs = parse_headers(head);
    let Some((_, ar)) = hs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authentication-results"))
    else {
        return false;
    };
    let value = strip_comments(ar).to_ascii_lowercase();
    let mut parts = value.split(';');
    let id = parts.next().unwrap_or("").trim();
    if let Some(want) = authserv
        && id.split_whitespace().next() != Some(want)
    {
        return false;
    }
    let on_site = |d: &str| {
        let d = d.trim().trim_start_matches('@');
        let d = d.rsplit('@').next().unwrap_or(d);
        registrable_domain(d).as_deref() == Some(site)
    };
    // The authserv-id segment may itself hold the first result when there is no id (Outlook).
    std::iter::once(id).chain(parts).any(|res| {
        let mut toks = res.split_whitespace();
        let Some(method) = toks.next() else {
            return false;
        };
        let props: Vec<&str> = toks.collect();
        let prop = |name: &str| {
            props
                .iter()
                .find_map(|p| p.strip_prefix(name).and_then(|r| r.strip_prefix('=')))
        };
        match method {
            "dmarc=pass" => prop("header.from").is_some_and(on_site),
            "dkim=pass" => prop("header.d").or(prop("header.i")).is_some_and(on_site),
            _ => false,
        }
    })
}

fn strip_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut depth = 0u32;
    for c in s.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::dkim_aligned;

    fn msg(ar: &str) -> Vec<u8> {
        format!("Authentication-Results: {ar}\r\nFrom: <a@example.com>\r\n\r\nbody").into_bytes()
    }

    #[test]
    fn gmail_shapes() {
        let ok = msg(
            "mx.google.com;\r\n       dkim=pass header.i=@example.com header.s=s;\r\n       spf=pass (google.com: x; y) smtp.mailfrom=a@example.com;\r\n       dmarc=pass (p=REJECT) header.from=example.com",
        );
        assert!(dkim_aligned(&ok, "example.com", Some("mx.google.com")));
        let spoof = msg(
            "mx.google.com; dkim=pass header.i=@evil-mailer.test; spf=pass smtp.mailfrom=b@evil-mailer.test; dmarc=fail header.from=example.com",
        );
        assert!(!dkim_aligned(&spoof, "example.com", Some("mx.google.com")));
        // A sub-domain signer is aligned (relaxed alignment).
        let sub = msg("mx.google.com; dkim=pass header.d=mail.example.com");
        assert!(dkim_aligned(&sub, "example.com", Some("mx.google.com")));
        // Wrong authserv-id: a header the sender wrote, not Gmail.
        assert!(!dkim_aligned(&ok, "example.com", Some("mx.other.test")));
        // Outlook style: no authserv-id.
        let ol = msg(
            "spf=pass smtp.mailfrom=example.com; dkim=pass (signature was verified) header.d=example.com;dmarc=pass action=none header.from=example.com;compauth=pass",
        );
        assert!(dkim_aligned(&ol, "example.com", None));
        assert!(!dkim_aligned(
            b"From: <a@example.com>\r\n\r\nno header",
            "example.com",
            None
        ));
    }

    #[test]
    fn only_the_topmost_header_counts() {
        let raw = b"Authentication-Results: mx.google.com; dkim=fail header.d=example.com\r\nAuthentication-Results: mx.google.com; dkim=pass header.d=example.com\r\n\r\nx";
        assert!(!dkim_aligned(raw, "example.com", Some("mx.google.com")));
    }
}
