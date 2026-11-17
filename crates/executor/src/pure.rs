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

/// What kind of field a DOM element is, judged from its tag and attributes only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FieldKind {
    /// `input[type=password]`.
    Password,
    /// A one-time-code input (`autocomplete=one-time-code`, or named like one).
    Code,
    /// `input[type=email]`, or an input whose autocomplete says email.
    Email,
    /// A plain text-like input (`text`, `tel`, `number`, `search`, `url`, no type...).
    TextInput,
    /// `textarea` or a contenteditable element.
    TextArea,
    /// `<select>`.
    Select,
    /// Anything that takes no typed text: hidden, file, submit, checkbox, a div...
    Other,
}

impl FieldKind {
    /// The label a snapshot shows for it, if any.
    pub(crate) fn label(self) -> Option<&'static str> {
        match self {
            Self::Password => Some("password"),
            Self::Code => Some("code"),
            Self::Email => Some("email"),
            Self::TextInput | Self::TextArea => Some("text"),
            Self::Select | Self::Other => None,
        }
    }
}

/// Value of `name` in a `DOM.describeNode` node's flat `attributes` list.
fn node_attr<'a>(node: &'a Value, name: &str) -> Option<&'a str> {
    attr(node, name)
}

/// Same rules as the executor's `OTP_FIELD` selector, on attributes.
fn code_like(node: &Value) -> bool {
    let lower = |k: &str| node_attr(node, k).map(str::to_ascii_lowercase);
    let ac = lower("autocomplete").unwrap_or_default();
    if ac.split_whitespace().any(|t| t == "one-time-code") {
        return true;
    }
    let (name, id) = (
        lower("name").unwrap_or_default(),
        lower("id").unwrap_or_default(),
    );
    name.contains("otp")
        || id.contains("otp")
        || name == "code"
        || id == "code"
        || name.contains("one-time")
        || name.contains("onetime")
        || name.contains("verification")
}

/// The field kind of a `DOM.describeNode` result's `node` (`nodeName` + `attributes`).
pub(crate) fn field_kind(node: &Value) -> FieldKind {
    let tag = node["nodeName"].as_str().unwrap_or("").to_ascii_uppercase();
    let editable =
        node_attr(node, "contenteditable").is_some_and(|v| !v.eq_ignore_ascii_case("false"));
    match tag.as_str() {
        "INPUT" => {
            let ty = node_attr(node, "type")
                .unwrap_or("text")
                .trim()
                .to_ascii_lowercase();
            match ty.as_str() {
                "password" => FieldKind::Password,
                "hidden" | "file" | "submit" | "button" | "image" | "reset" | "checkbox"
                | "radio" | "range" | "color" => FieldKind::Other,
                _ if code_like(node) => FieldKind::Code,
                "email" => FieldKind::Email,
                _ if node_attr(node, "autocomplete").is_some_and(|a| {
                    a.to_ascii_lowercase()
                        .split_whitespace()
                        .any(|t| t == "email")
                }) =>
                {
                    FieldKind::Email
                }
                "" | "text" | "tel" | "number" | "search" | "url" | "date" | "month" | "week"
                | "time" | "datetime-local" => FieldKind::TextInput,
                _ => FieldKind::Other,
            }
        }
        "TEXTAREA" => FieldKind::TextArea,
        "SELECT" => FieldKind::Select,
        _ if editable => FieldKind::TextArea,
        _ => FieldKind::Other,
    }
}

/// Is this `input` type one an emailed code may go into (besides a code-like field)?
pub(crate) fn plain_input_type(node: &Value) -> Option<String> {
    if !node["nodeName"]
        .as_str()
        .is_some_and(|t| t.eq_ignore_ascii_case("input"))
    {
        return None;
    }
    Some(
        node_attr(node, "type")
            .unwrap_or("text")
            .trim()
            .to_ascii_lowercase(),
    )
}

/// Backend ids of the field nodes (textbox, combobox...) in an AX tree, for kinds.
pub(crate) fn field_ids(tree: &Value) -> Vec<u64> {
    tree["nodes"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|n| n["ignored"].as_bool() != Some(true) && FIELDS.contains(&role(n)))
                .filter_map(|n| n["backendDOMNodeId"].as_u64())
                .collect()
        })
        .unwrap_or_default()
}

/// An `<option>` from `DOM.describeNode` (depth 1): its label (the `label`
/// attribute, else its text) and its value (the `value` attribute, else the label).
pub(crate) fn option_label_value(node: &Value) -> (String, String) {
    let text: String = node["children"]
        .as_array()
        .map(|k| {
            k.iter()
                .filter_map(|c| c["nodeValue"].as_str())
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default();
    let label = attr(node, "label")
        .map(str::to_string)
        .unwrap_or(text)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let value = attr(node, "value").map_or_else(|| label.clone(), str::to_string);
    (label, value)
}

/// Most option labels a snapshot lists for one `<select>`.
const MAX_OPTIONS: usize = 25;

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
    ax_lines_kinds(tree, &HashMap::new())
}

/// [`ax_lines`] with each field's kind (by backend node id): text fields show
/// `(password, empty)`, `(code, filled)`, `(email, ...)`, `(text, ...)`; a `<select>`
/// shows its chosen option and the options it offers. A field with no known kind
/// shows only `(filled)` / `(empty)`. Text-field values are never shown.
pub(crate) fn ax_lines_kinds(tree: &Value, kinds: &HashMap<u64, FieldKind>) -> Vec<String> {
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
            let state = if filled { "filled" } else { "empty" };
            match kinds.get(&id) {
                Some(FieldKind::Select) => {
                    // A select's value is the label of a choice, not typed text.
                    let chosen = clean(n["value"]["value"].as_str().unwrap_or(""));
                    let opts = select_options(n, &by_id);
                    line.push_str(&format!(" (select: \"{chosen}\""));
                    if !opts.is_empty() {
                        line.push_str(&format!("; options: {}", opts.join(" | ")));
                    }
                    line.push(')');
                }
                Some(k) => match k.label() {
                    Some(l) => line.push_str(&format!(" ({l}, {state})")),
                    None => line.push_str(&format!(" ({state})")),
                },
                None => line.push_str(&format!(" ({state})")),
            }
        } else if matches!(r, "checkbox" | "radio" | "switch") {
            match checked(n) {
                Some(true) => line.push_str(" (checked)"),
                Some(false) => line.push_str(" (unchecked)"),
                None => {}
            }
        }
        out.push(line);
        last_name = nm;
        if out.len() >= MAX_LINES {
            break;
        }
    }
    out
}

/// Labels of a `<select>`'s options (its AX descendants), quoted, at most `MAX_OPTIONS`.
fn select_options(n: &Value, by_id: &HashMap<&str, &Value>) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack: Vec<&Value> = vec![n];
    let mut hops = 0;
    while let Some(cur) = stack.pop() {
        hops += 1;
        if hops > 2000 || out.len() >= MAX_OPTIONS {
            break;
        }
        if !std::ptr::eq(cur, n) && matches!(role(cur), "MenuListOption" | "option") {
            out.push(format!("\"{}\"", clean(name(cur))));
            continue;
        }
        if let Some(kids) = cur["childIds"].as_array() {
            stack.extend(
                kids.iter()
                    .rev()
                    .filter_map(Value::as_str)
                    .filter_map(|k| by_id.get(k).copied()),
            );
        }
    }
    out
}

/// A checkbox's state from its AX `checked` property.
fn checked(n: &Value) -> Option<bool> {
    n["properties"].as_array()?.iter().find_map(|p| {
        (p["name"] == "checked").then(|| match &p["value"]["value"] {
            Value::Bool(b) => *b,
            Value::String(s) => s == "true" || s == "mixed",
            _ => false,
        })
    })
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

    fn dn(tag: &str, attrs: &[&str]) -> Value {
        json!({"nodeName": tag, "attributes": attrs})
    }

    #[test]
    fn field_kinds() {
        use FieldKind::*;
        assert_eq!(field_kind(&dn("INPUT", &["type", "password"])), Password);
        assert_eq!(field_kind(&dn("INPUT", &["type", "PASSWORD"])), Password);
        assert_eq!(
            field_kind(&dn("INPUT", &["autocomplete", "one-time-code"])),
            Code
        );
        assert_eq!(
            field_kind(&dn("INPUT", &["name", "otp_1", "type", "tel"])),
            Code
        );
        assert_eq!(field_kind(&dn("INPUT", &["id", "code"])), Code);
        // A password field named "code" is still a password field.
        assert_eq!(
            field_kind(&dn("INPUT", &["type", "password", "name", "code"])),
            Password
        );
        assert_eq!(field_kind(&dn("INPUT", &["type", "email"])), Email);
        assert_eq!(
            field_kind(&dn("INPUT", &["autocomplete", "username email"])),
            Email
        );
        assert_eq!(field_kind(&dn("INPUT", &[])), TextInput);
        assert_eq!(field_kind(&dn("INPUT", &["type", "tel"])), TextInput);
        assert_eq!(field_kind(&dn("INPUT", &["name", "postcode"])), TextInput);
        for t in ["hidden", "file", "submit", "checkbox", "button"] {
            assert_eq!(field_kind(&dn("INPUT", &["type", t])), Other, "{t}");
        }
        assert_eq!(field_kind(&dn("TEXTAREA", &[])), TextArea);
        assert_eq!(field_kind(&dn("SELECT", &[])), Select);
        assert_eq!(
            field_kind(&dn("DIV", &["contenteditable", "true"])),
            TextArea
        );
        assert_eq!(field_kind(&dn("DIV", &["contenteditable", "false"])), Other);
        assert_eq!(field_kind(&dn("DIV", &[])), Other);
    }

    #[test]
    fn snapshot_kinds_and_selects() {
        let t = json!({"nodes": [
            {"nodeId": "1", "childIds": ["2", "3", "4", "5", "8"], "role": {"value": "RootWebArea"}},
            {"nodeId": "2", "parentId": "1", "role": {"value": "textbox"}, "name": {"value": "Password"},
             "value": {"value": "fixture-pw-123"}, "backendDOMNodeId": 12},
            {"nodeId": "3", "parentId": "1", "role": {"value": "textbox"}, "name": {"value": "Code"}, "backendDOMNodeId": 14},
            {"nodeId": "4", "parentId": "1", "role": {"value": "textbox"}, "name": {"value": "First name"},
             "value": {"value": "Ada"}, "backendDOMNodeId": 15},
            {"nodeId": "5", "parentId": "1", "childIds": ["6"], "role": {"value": "combobox"}, "name": {"value": "Country"},
             "value": {"value": "Germany"}, "backendDOMNodeId": 16},
            {"nodeId": "6", "parentId": "5", "childIds": ["7", "9"], "role": {"value": "MenuListPopup"}},
            {"nodeId": "7", "parentId": "6", "role": {"value": "MenuListOption"}, "name": {"value": "India"}},
            {"nodeId": "9", "parentId": "6", "role": {"value": "MenuListOption"}, "name": {"value": "Germany"}},
            {"nodeId": "8", "parentId": "1", "role": {"value": "checkbox"}, "name": {"value": "I agree"},
             "properties": [{"name": "checked", "value": {"type": "tristate", "value": "true"}}], "backendDOMNodeId": 17}
        ]});
        let kinds: HashMap<u64, FieldKind> = [
            (12, FieldKind::Password),
            (14, FieldKind::Code),
            (15, FieldKind::TextInput),
            (16, FieldKind::Select),
        ]
        .into();
        let lines = ax_lines_kinds(&t, &kinds);
        assert_eq!(
            lines,
            vec![
                "[12] textbox \"Password\" (password, filled)",
                "[14] textbox \"Code\" (code, empty)",
                "[15] textbox \"First name\" (text, filled)",
                "[16] combobox \"Country\" (select: \"Germany\"; options: \"India\" | \"Germany\")",
                "[17] checkbox \"I agree\" (checked)",
            ]
        );
        let all = lines.join("\n");
        assert!(!all.contains("fixture-pw-123") && !all.contains("Ada"));
        // Without kinds (e.g. out of time) a select is just filled/empty: no label shown.
        assert!(ax_lines(&t).contains(&"[16] combobox \"Country\" (filled)".to_string()));
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
