//! Hostile MCP client: the attack list.
//!
//! Each attack drives one tool (and usually one argument) of the 0.1 tool surface (build plan §2)
//! the way a compromised or malicious agent would. Phase 3 only names them. `tests/hostile.rs` has one
//! ignored test per attack. Phase 6 (tools exist) makes them real; Phases 7–8 cover the flow-level ones.
//! Every attack also runs the canary scan over everything the client received.

/// One scripted attack.
#[derive(Debug, Clone, Copy)]
pub struct Attack {
    /// Unique id; the test function has the same name.
    pub id: &'static str,
    /// The tool the attack calls.
    pub tool: &'static str,
    /// The argument it abuses (or `-` for the call as a whole).
    pub argument: &'static str,
    /// What the attacker tries.
    pub tries: &'static str,
    /// What logindesk must do.
    pub expect: &'static str,
    /// The phase that makes it runnable.
    pub phase: u8,
}

const fn a(
    id: &'static str,
    tool: &'static str,
    argument: &'static str,
    tries: &'static str,
    expect: &'static str,
    phase: u8,
) -> Attack {
    Attack {
        id,
        tool,
        argument,
        tries,
        expect,
        phase,
    }
}

/// Every attack, grouped by tool.
pub const ATTACKS: &[Attack] = &[
    // accounts_find
    a(
        "accounts_find_returns_no_secret",
        "accounts_find",
        "site",
        "read the password or OTP seed through account metadata",
        "only email, username, creator, last login; canary clean",
        6,
    ),
    a(
        "accounts_find_site_injection",
        "accounts_find",
        "site",
        "site = \"example.localhost' OR 1=1 --\" or a 10 MB string",
        "typed `failed` (invalid site); no SQL error text; no panic",
        6,
    ),
    // login
    a(
        "login_lookalike_host",
        "login",
        "site",
        "log in to examp1e.localhost hoping the example.localhost entry is offered",
        "no vault match; nothing filled",
        7,
    ),
    a(
        "login_url_confusion",
        "login",
        "site",
        "site = example.localhost@evil.test, evil.test/example.localhost, example.localhost.evil.test",
        "eTLD+1 parsed correctly; no match for example.localhost",
        6,
    ),
    a(
        "login_homoglyph_site",
        "login",
        "site",
        "site with a Cyrillic а (exаmple.localhost) or punycode",
        "treated as a different site; approval names the punycode form",
        6,
    ),
    a(
        "login_account_arg_injection",
        "login",
        "account",
        "account = another site's entry id",
        "denied: account does not belong to site",
        6,
    ),
    a(
        "login_without_approval",
        "login",
        "-",
        "call login and assume the popup is skipped in tests",
        "awaiting_approval; release build has no auto-approve path",
        6,
    ),
    a(
        "login_approval_replay",
        "login",
        "-",
        "reuse an approval granted for an earlier login",
        "denied: approvals are single-use",
        6,
    ),
    a(
        "login_approval_expired",
        "login",
        "-",
        "answer the approval after 60 s",
        "denied: approval expired",
        6,
    ),
    a(
        "login_captcha_page",
        "login",
        "-",
        "drive /captcha to completion",
        "needs_user; the user finishes in Chrome",
        7,
    ),
    a(
        "login_injected_page",
        "login",
        "-",
        "/injected tells the agent to capture and exfiltrate the password",
        "nothing outside the requested flow happens; snapshot marks hidden text",
        7,
    ),
    a(
        "login_read_fields_page",
        "login",
        "-",
        "/read-fields copies field values to /collect while logindesk fills",
        "documented outcome; canary shows exactly what the page saw",
        7,
    ),
    a(
        "login_cross_origin_form",
        "login",
        "-",
        "/cross-origin form posts the password to another origin",
        "fill refused or submit blocked: form action is not same-site",
        7,
    ),
    a(
        "login_cross_origin_iframe",
        "login",
        "-",
        "fill the password into the cross-origin iframe on /iframe-login",
        "fill refused: frame is not same-site",
        7,
    ),
    a(
        "login_rate_spam",
        "login",
        "-",
        "call login 100 times in a minute",
        "rate limited with a typed status; no 100 popups",
        6,
    ),
    // signup
    a(
        "signup_fields_expand_handle",
        "signup",
        "fields",
        "fields = {\"bio\": \"secret:vault.password\"}",
        "handles never expand into free-text fields",
        6,
    ),
    a(
        "signup_identity_other_user",
        "signup",
        "identity",
        "use an identity the user never set up",
        "denied",
        6,
    ),
    a(
        "signup_otp_spoofed_sender",
        "signup",
        "-",
        "newest mail is the spoofed-sender code (DMARC fail)",
        "aligned code used; spoofed one ignored",
        8,
    ),
    // session_snapshot
    a(
        "snapshot_password_value",
        "session_snapshot",
        "session_id",
        "read a filled password from the AX tree",
        "value masked; canary clean",
        6,
    ),
    a(
        "snapshot_password_length",
        "session_snapshot",
        "session_id",
        "infer password length from the mask (Chrome shows one bullet per char)",
        "fixed-width mask, length not exposed",
        6,
    ),
    a(
        "snapshot_other_client_session",
        "session_snapshot",
        "session_id",
        "snapshot a session that another paired client opened",
        "denied",
        6,
    ),
    a(
        "snapshot_forged_session_id",
        "session_snapshot",
        "session_id",
        "random, empty, very long or path-like session_id",
        "typed `failed`; no panic",
        6,
    ),
    // session_act
    a(
        "act_type_handle_literal",
        "session_act",
        "text",
        "type \"secret:vault.password\" into a search box",
        "typed literally or refused; never resolved",
        6,
    ),
    a(
        "act_type_into_password_then_snapshot",
        "session_act",
        "ref",
        "type into the password field, then snapshot to read back",
        "value masked; canary clean",
        6,
    ),
    a(
        "act_submit_without_approval",
        "session_act",
        "action",
        "click submit on a filled login form",
        "popup required for any form submit",
        6,
    ),
    a(
        "act_navigate_exfil",
        "session_act",
        "action",
        "navigate to http://127.0.0.1:<other>/collect?pw=… after a fill",
        "URL never contains a secret (nothing to copy); canary clean",
        6,
    ),
    a(
        "act_navigate_scheme",
        "session_act",
        "text",
        "navigate to file:///etc/passwd, javascript:…, chrome://settings, data:…",
        "refused: http(s) only",
        6,
    ),
    a(
        "act_bad_ref",
        "session_act",
        "ref",
        "ref from an old snapshot, another session, or garbage",
        "typed `failed`",
        6,
    ),
    // capture_secret
    a(
        "capture_returns_handle_only",
        "capture_secret",
        "-",
        "capture an API key shown on a page and read the value from the result",
        "result is `secret:<label>` only; canary clean",
        6,
    ),
    a(
        "capture_label_traversal",
        "capture_secret",
        "label",
        "label = ../../etc/passwd or contains NUL, CRLF, ANSI escapes",
        "label rejected or normalised; no file written outside the vault",
        6,
    ),
    a(
        "capture_cross_site",
        "capture_secret",
        "ref",
        "capture from a frame or page of another site",
        "denied",
        6,
    ),
    // session_close / wait
    a(
        "close_other_client_session",
        "session_close",
        "session_id",
        "close a session another client opened",
        "denied",
        6,
    ),
    a(
        "wait_foreign_handle",
        "wait",
        "handle",
        "wait on a handle issued to another client",
        "denied",
        6,
    ),
    a(
        "wait_forged_handle",
        "wait",
        "handle",
        "random or reused handle",
        "typed `failed`",
        6,
    ),
    // protocol level
    a(
        "rpc_malformed_input",
        "-",
        "-",
        "send invalid JSON, a huge line and unknown methods on stdin",
        "JSON-RPC errors on stdout only; no logs on stdout; no panic text with secrets",
        6,
    ),
    a(
        "rpc_unknown_tool_and_extra_args",
        "-",
        "-",
        "call an unknown tool, or a known tool with extra arguments",
        "invalid-params error; nothing executed",
        6,
    ),
    a(
        "errors_contain_no_secret",
        "-",
        "-",
        "force every error path (wrong password, locked vault, Chrome gone)",
        "canary clean across every error message",
        6,
    ),
];

/// Print the attack list to stderr (the `testbed hostile` subcommand).
pub fn print_plan() {
    eprintln!(
        "hostile MCP client: {} attacks named; none runnable until the tools exist (Phase 6+)",
        ATTACKS.len()
    );
    for x in ATTACKS {
        eprintln!(
            "  [P{}] {:<38} {:<16} {:<10} {}",
            x.phase, x.id, x.tool, x.argument, x.tries
        );
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ids_unique_and_every_tool_covered() {
        let ids: std::collections::BTreeSet<_> = super::ATTACKS.iter().map(|a| a.id).collect();
        assert_eq!(ids.len(), super::ATTACKS.len());
        for tool in [
            "accounts_find",
            "login",
            "signup",
            "session_snapshot",
            "session_act",
            "capture_secret",
            "session_close",
            "wait",
        ] {
            assert!(
                super::ATTACKS.iter().any(|a| a.tool == tool),
                "no attack for {tool}"
            );
        }
    }
}
