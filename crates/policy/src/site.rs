//! The one eTLD+1 function in the workspace (contract §6).

/// Lowercase ASCII registrable domain (eTLD+1) of `host`, or None.
/// IP literals, bare `localhost`, empty and non-ASCII input → None
/// (callers punycode first). `*.localhost` and `*.test` resolve normally.
pub fn registrable_domain(host: &str) -> Option<String> {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() || !h.is_ascii() || h == "localhost" || h.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    if h.starts_with('[') || h.contains(':') || h.split('.').any(str::is_empty) {
        return None;
    }
    // psl treats unknown TLDs (like .localhost, .test) with the implicit "*" rule,
    // so `a.example.localhost` → `example.localhost`.
    let d = psl::domain(h.as_bytes())?;
    std::str::from_utf8(d.as_bytes()).ok().map(str::to_string)
}

/// Registrable domain of a URL's host, or None.
pub fn url_site(u: &url::Url) -> Option<String> {
    u.host_str().and_then(registrable_domain)
}

/// What the user typed as a site: a bare host, or a URL. Returns the registrable domain.
pub fn site_of(input: &str) -> Option<String> {
    let t = input.trim();
    if t.contains("://") {
        url::Url::parse(t).ok().as_ref().and_then(url_site)
    } else {
        let host = t.split(['/', ':']).next().unwrap_or("");
        registrable_domain(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains() {
        assert_eq!(
            registrable_domain("www.example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            registrable_domain("a.b.example.co.uk").as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(
            registrable_domain("example.localhost").as_deref(),
            Some("example.localhost")
        );
        assert_eq!(
            registrable_domain("x.example.localhost").as_deref(),
            Some("example.localhost")
        );
        assert_eq!(
            registrable_domain("examp1e.localhost").as_deref(),
            Some("examp1e.localhost")
        );
        assert_eq!(
            registrable_domain("shop.example.test").as_deref(),
            Some("example.test")
        );
        assert_eq!(registrable_domain("localhost"), None);
        assert_eq!(registrable_domain("127.0.0.1"), None);
        assert_eq!(registrable_domain(""), None);
        assert_eq!(registrable_domain("com"), None);
        assert_eq!(registrable_domain("exämple.com"), None);
    }

    #[test]
    fn inputs() {
        assert_eq!(
            site_of("http://example.localhost:8080/login").as_deref(),
            Some("example.localhost")
        );
        assert_eq!(
            site_of("example.localhost:8080").as_deref(),
            Some("example.localhost")
        );
        assert_eq!(
            site_of("https://www.github.com/").as_deref(),
            Some("github.com")
        );
    }
}
