//! Pure helpers (no browser): the masked AX rendering and the URL fence.

use std::collections::{HashMap, HashSet};

use serde_json::Value;
use url::Url;

/// Roles shown in a snapshot.
const SHOWN: &[&str] = &[
    "heading",
    "link",
    "button",
    "textbox",
    "searchbox",
    "combobox",
    "spinbutton",
    "checkbox",
    "radio",
    "switch",
    "StaticText",
    "alert",
    "status",
    "dialog",
    "alertdialog",
    "img",
    "tab",
    "menuitem",
    "option",
];

/// Roles whose value is user input: shown as `(filled)` / `(empty)`, and nothing
/// beneath them is shown (Chrome puts the typed text in child StaticText nodes).
const FIELDS: &[&str] = &["textbox", "searchbox", "combobox", "spinbutton"];

/// Most lines one snapshot returns.
pub(crate) const MAX_LINES: usize = 2000;
/// Longest name shown, in chars.
const MAX_NAME: usize = 200;

fn role(n: &Value) -> &str {
    n["role"]["value"].as_str().unwrap_or("")
}

fn name(n: &Value) -> &str {
    n["name"]["value"].as_str().unwrap_or("")
}

/// Render `Accessibility.getFullAXTree`'s reply as `[ref] role "name"` lines, in
/// document order (depth-first over `childIds`). Text fields show `(filled)` /
/// `(empty)`; the walk never descends into a field, so no value (nor the StaticText
/// Chrome puts under a field) reaches the output. Nodes not reachable from the root
/// are dropped.
pub(crate) fn ax_lines(tree: &Value) -> Vec<String> {
    let Some(nodes) = tree["nodes"].as_array() else {
        return Vec::new();
    };
    let by_id: HashMap<&str, &Value> = nodes
        .iter()
        .filter_map(|n| n["nodeId"].as_str().map(|id| (id, n)))
        .collect();
    let mut stack: Vec<&Value> = nodes
        .iter()
        .filter(|n| n["parentId"].as_str().is_none())
        .rev()
        .collect();
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut last_name = String::new();
    while let Some(n) = stack.pop() {
        if !seen.insert(n["nodeId"].as_str().unwrap_or("")) {
            continue; // malformed (cyclic) tree
        }
        let r = role(n);
        let field = FIELDS.contains(&r);
        if !field && let Some(kids) = n["childIds"].as_array() {
            stack.extend(
                kids.iter()
                    .rev()
                    .filter_map(Value::as_str)
                    .filter_map(|k| by_id.get(k).copied()),
            );
        }
        if n["ignored"].as_bool() == Some(true) || !SHOWN.contains(&r) {
            continue;
        }
        let nm = clean(name(n));
        if r == "StaticText" && (nm.is_empty() || nm == last_name) {
            // Text already shown as its parent's name (heading, link, button...).
            continue;
        }
        let id = n["backendDOMNodeId"].as_u64().unwrap_or(0);
        let mut line = format!("[{id}] {r} \"{nm}\"");
        if field {
            let filled = n["value"]["value"].as_str().is_some_and(|v| !v.is_empty());
            line.push_str(if filled { " (filled)" } else { " (empty)" });
        }
        out.push(line);
        last_name = nm;
        if out.len() >= MAX_LINES {
            break;
        }
    }
    out
}

/// One line, quotes escaped, at most `MAX_NAME` chars.
fn clean(s: &str) -> String {
    let flat: String = s
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(MAX_NAME)
        .collect();
    flat.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Every non-ignored AX name, lowercased and joined (for the CAPTCHA text check).
/// Links are skipped: a link *to* a CAPTCHA page is not a CAPTCHA.
pub(crate) fn ax_text(tree: &Value) -> String {
    tree["nodes"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|n| n["ignored"].as_bool() != Some(true) && role(n) != "link")
                .map(|n| name(n).to_lowercase())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

/// True when a non-ignored alert node with text is on the page.
pub(crate) fn ax_has_alert(tree: &Value) -> bool {
    tree["nodes"].as_array().is_some_and(|a| {
        a.iter().any(|n| {
            n["ignored"].as_bool() != Some(true) && matches!(role(n), "alert" | "alertdialog")
        })
    })
}

/// Is `url` on `site` (registrable domain)?
pub(crate) fn on_site(url: &Url, site: &str) -> bool {
    logindesk_policy::url_site(url).as_deref() == Some(site)
}

/// Resolve a form `action` against the page URL (empty or missing = the page URL) and
/// check it is on `site`. Unparseable, `javascript:`, IP and other hosts all fail.
pub(crate) fn action_on_site(page: &Url, action: Option<&str>, site: &str) -> bool {
    let target = match action.map(str::trim) {
        None | Some("") => page.clone(),
        Some(a) => match page.join(a) {
            Ok(u) => u,
            Err(_) => return false,
        },
    };
    matches!(target.scheme(), "http" | "https") && on_site(&target, site)
}

/// Value of `name` in `DOM.getAttributes`' flat `[k, v, k, v...]` list.
pub(crate) fn attr<'a>(attrs: &'a Value, name: &str) -> Option<&'a str> {
    attrs["attributes"]
        .as_array()?
        .chunks(2)
        .find(|kv| kv[0].as_str().is_some_and(|k| k.eq_ignore_ascii_case(name)))
        .and_then(|kv| kv.get(1))
        .and_then(Value::as_str)
}

/// Centre of a `DOM.getBoxModel` content quad.
pub(crate) fn quad_centre(model: &Value) -> Option<(f64, f64)> {
    let q = model["model"]["content"].as_array()?;
    if q.len() != 8 {
        return None;
    }
    let v: Vec<f64> = q.iter().filter_map(Value::as_f64).collect();
    if v.len() != 8 {
        return None;
    }
    Some((
        (v[0] + v[2] + v[4] + v[6]) / 4.0,
        (v[1] + v[3] + v[5] + v[7]) / 4.0,
    ))
}

/// A `DOM.getBoxModel` reply for something a user could see: a real size, and not
/// pushed off-screen to the left or top (a common honeypot trick).
pub(crate) fn box_visible(model: &Value) -> bool {
    let m = &model["model"];
    let (w, h) = (
        m["width"].as_f64().unwrap_or(0.0),
        m["height"].as_f64().unwrap_or(0.0),
    );
    if w < 1.0 || h < 1.0 {
        return false;
    }
    let Some(q) = m["border"].as_array().or_else(|| m["content"].as_array()) else {
        return false;
    };
    let v: Vec<f64> = q.iter().filter_map(Value::as_f64).collect();
    if v.len() != 8 {
        return false;
    }
    let max_x = v[0].max(v[2]).max(v[4]).max(v[6]);
    let max_y = v[1].max(v[3]).max(v[5]).max(v[7]);
    max_x > 0.0 && max_y > 0.0
}

/// Buttons and links whose accessible name is an opener word, best group first, in
/// page order within a group. Long names (sentences) and "... with Google"-style
/// third-party sign-ins are skipped.
pub(crate) fn opener_candidates(tree: &Value, groups: &[&[&str]], max_len: usize) -> Vec<u64> {
    let Some(nodes) = tree["nodes"].as_array() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for words in groups {
        for n in nodes {
            if n["ignored"].as_bool() == Some(true) || !matches!(role(n), "button" | "link") {
                continue;
            }
            let nm = name(n).trim().to_lowercase();
            if nm.is_empty() || nm.chars().count() > max_len || nm.contains(" with ") {
                continue;
            }
            if words.iter().any(|w| nm.contains(w))
                && let Some(id) = n["backendDOMNodeId"].as_u64()
                && !out.contains(&id)
            {
                out.push(id);
            }
        }
    }
    out
}

/// Clicking a link with this `href` keeps us on `site`: an in-page link (`#...`,
/// `javascript:`), or a URL whose registrable domain is `site`.
pub(crate) fn href_stays_on_site(page: &Url, href: &str, site: &str) -> bool {
    let h = href.trim();
    if h.is_empty() || h.starts_with('#') || h.to_ascii_lowercase().starts_with("javascript:") {
        return true;
    }
    action_on_site(page, Some(h), site)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use serde_json::json;

    fn tree() -> Value {
        json!({"nodes": [
            {"nodeId": "1", "childIds": ["2", "4", "7", "9", "10", "11", "12", "13"], "role": {"value": "RootWebArea"}, "name": {"value": "Sign in"}, "backendDOMNodeId": 1},
            {"nodeId": "2", "childIds": ["3"], "parentId": "1", "role": {"value": "heading"}, "name": {"value": "Sign in"}, "backendDOMNodeId": 5},
            {"nodeId": "3", "parentId": "2", "role": {"value": "StaticText"}, "name": {"value": "Sign in"}, "backendDOMNodeId": 6},
            {"nodeId": "4", "childIds": ["5"], "parentId": "1", "role": {"value": "textbox"}, "name": {"value": "Email"},
             "value": {"type": "string", "value": "alice@example.localhost"}, "backendDOMNodeId": 7},
            {"nodeId": "5", "childIds": ["6"], "parentId": "4", "role": {"value": "generic"}, "backendDOMNodeId": 8},
            {"nodeId": "6", "parentId": "5", "role": {"value": "StaticText"}, "name": {"value": "alice@example.localhost"}, "backendDOMNodeId": 9},
            {"nodeId": "7", "childIds": ["8"], "parentId": "1", "role": {"value": "textbox"}, "name": {"value": "Password"},
             "value": {"type": "string", "value": "fixture-pw-123"}, "backendDOMNodeId": 10},
            {"nodeId": "8", "parentId": "7", "role": {"value": "StaticText"}, "name": {"value": "fixture-pw-123"}, "backendDOMNodeId": 11},
            {"nodeId": "9", "parentId": "1", "role": {"value": "textbox"}, "name": {"value": "Search"}, "backendDOMNodeId": 12},
            {"nodeId": "10", "parentId": "1", "role": {"value": "button"}, "name": {"value": "Sign \"in\"\nnow"}, "backendDOMNodeId": 13},
            {"nodeId": "11", "parentId": "1", "ignored": true, "role": {"value": "StaticText"}, "name": {"value": "hidden instructions"}, "backendDOMNodeId": 14},
            {"nodeId": "12", "parentId": "1", "role": {"value": "alert"}, "name": {"value": "Wrong email or password."}, "backendDOMNodeId": 15},
            {"nodeId": "13", "parentId": "1", "role": {"value": "link"}, "name": {"value": "Login behind a fake CAPTCHA"}, "backendDOMNodeId": 16}
        ]})
    }

    #[test]
    fn snapshot_masks_field_values() {
        let lines = ax_lines(&tree());
        let all = lines.join("\n");
        assert!(!all.contains("alice@example.localhost"), "{all}");
        assert!(!all.contains("fixture-pw-123"), "{all}");
        assert!(lines.contains(&"[7] textbox \"Email\" (filled)".to_string()));
        assert!(lines.contains(&"[10] textbox \"Password\" (filled)".to_string()));
        assert!(lines.contains(&"[12] textbox \"Search\" (empty)".to_string()));
        assert!(lines.contains(&"[5] heading \"Sign in\"".to_string()));
        // The heading's own text is not repeated, ignored nodes never show.
        assert_eq!(lines.iter().filter(|l| l.contains("Sign in\"")).count(), 1);
        assert!(!all.contains("hidden instructions"));
        // Document order: heading, then fields in page order.
        let pos = |p: &str| lines.iter().position(|l| l.starts_with(p)).unwrap();
        assert!(pos("[5]") < pos("[7]") && pos("[7]") < pos("[10]") && pos("[10]") < pos("[12]"));
        // One line per node; quotes escaped.
        assert!(lines.contains(&"[13] button \"Sign \\\"in\\\" now\"".to_string()));
    }

    #[test]
    fn alert_and_captcha_text() {
        assert!(ax_has_alert(&tree()));
        assert!(!ax_text(&tree()).contains("captcha"), "links don't count");
        assert!(!ax_has_alert(&json!({"nodes": []})));
        assert!(ax_lines(&json!({})).is_empty());
    }

    #[test]
    fn cyclic_and_orphan_nodes_terminate() {
        let t = json!({"nodes": [
            {"nodeId": "1", "childIds": ["2"], "role": {"value": "RootWebArea"}},
            {"nodeId": "2", "parentId": "1", "childIds": ["3"], "role": {"value": "heading"}, "name": {"value": "h"}},
            {"nodeId": "3", "parentId": "2", "childIds": ["2"], "role": {"value": "StaticText"}, "name": {"value": "x"}},
            {"nodeId": "9", "parentId": "8", "role": {"value": "StaticText"}, "name": {"value": "orphan"}}
        ]});
        assert_eq!(
            ax_lines(&t),
            vec!["[0] heading \"h\"", "[0] StaticText \"x\""]
        );
    }

    #[test]
    fn fence() {
        let page = Url::parse("http://example.localhost:4000/login").unwrap();
        let site = "example.localhost";
        assert!(on_site(&page, site));
        assert!(action_on_site(&page, None, site));
        assert!(action_on_site(&page, Some(""), site));
        assert!(action_on_site(&page, Some("/login"), site));
        assert!(action_on_site(&page, Some("?next=1"), site));
        assert!(action_on_site(
            &page,
            Some("https://auth.example.localhost/x"),
            site
        ));
        assert!(!action_on_site(
            &page,
            Some("http://127.0.0.1:4001/collect"),
            site
        ));
        assert!(!action_on_site(
            &page,
            Some("//examp1e.localhost/collect"),
            site
        ));
        assert!(!action_on_site(&page, Some("javascript:steal()"), site));
        let look = Url::parse("http://examp1e.localhost:4000/login").unwrap();
        assert!(!on_site(&look, site));
        assert!(!action_on_site(&look, Some("/collect"), site));
        let ip = Url::parse("http://127.0.0.1:4000/login").unwrap();
        assert!(!on_site(&ip, site));
    }

    #[test]
    fn visibility() {
        let on = json!({"model": {"width": 120, "height": 20,
            "border": [10.0, 10.0, 130.0, 10.0, 130.0, 30.0, 10.0, 30.0]}});
        assert!(box_visible(&on));
        let off = json!({"model": {"width": 120, "height": 20,
            "border": [-9999.0, 0.0, -9879.0, 0.0, -9879.0, 20.0, -9999.0, 20.0]}});
        assert!(!box_visible(&off));
        let zero = json!({"model": {"width": 0, "height": 0,
            "border": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]}});
        assert!(!box_visible(&zero));
        assert!(!box_visible(&json!({})));
    }

    #[test]
    fn openers() {
        let t = json!({"nodes": [
            {"nodeId": "1", "role": {"value": "link"}, "name": {"value": "Sign in with Google"}, "backendDOMNodeId": 1},
            {"nodeId": "2", "role": {"value": "link"}, "name": {"value": "Log in"}, "backendDOMNodeId": 2},
            {"nodeId": "3", "role": {"value": "button"}, "name": {"value": "Create account"}, "backendDOMNodeId": 3},
            {"nodeId": "4", "role": {"value": "button"}, "name": {"value": "Already have an account? Log in to keep going today"}, "backendDOMNodeId": 4},
            {"nodeId": "5", "ignored": true, "role": {"value": "button"}, "name": {"value": "Sign up"}, "backendDOMNodeId": 5},
            {"nodeId": "6", "role": {"value": "StaticText"}, "name": {"value": "Sign up"}, "backendDOMNodeId": 6}
        ]});
        let signup: &[&[&str]] = &[&["sign up", "create account"], &["sign in", "log in"]];
        assert_eq!(opener_candidates(&t, signup, 40), vec![3, 2]);
        let login: &[&[&str]] = &[&["sign in", "log in"]];
        assert_eq!(opener_candidates(&t, login, 40), vec![2]);
    }

    #[test]
    fn opener_links_stay_on_site() {
        let page = Url::parse("https://app.example.com/").unwrap();
        assert!(href_stays_on_site(&page, "#login", "example.com"));
        assert!(href_stays_on_site(
            &page,
            "javascript:void(0)",
            "example.com"
        ));
        assert!(href_stays_on_site(&page, "/signin", "example.com"));
        assert!(href_stays_on_site(
            &page,
            "https://auth.example.com/x",
            "example.com"
        ));
        assert!(!href_stays_on_site(
            &page,
            "https://accounts.google.com/o",
            "example.com"
        ));
    }

    #[test]
    fn attrs_and_quads() {
        let a = json!({"attributes": ["method", "post", "ACTION", "/login"]});
        assert_eq!(attr(&a, "action"), Some("/login"));
        assert_eq!(attr(&a, "id"), None);
        let m = json!({"model": {"content": [0.0, 0.0, 10.0, 0.0, 10.0, 20.0, 0.0, 20.0]}});
        assert_eq!(quad_centre(&m), Some((5.0, 10.0)));
        assert_eq!(quad_centre(&json!({})), None);
    }
}
