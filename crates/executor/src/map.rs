//! Finding the fields on real pages: wait for JS-built forms, ignore hidden and
//! off-screen inputs (honeypots), and open a "Sign in" / "Sign up" panel when no form
//! is showing. Nothing here fills a secret or submits.

use std::time::{Duration, Instant};

use serde_json::{Value, json};

use std::collections::HashMap;

use logindesk_core::SecretString;

use crate::pure::FieldKind;
use crate::{
    EMAIL_FIELDS, ExecError, MapFail, NAME_FIELDS, NEW_PW, OTP_FIELD, SUBMIT_LOAD, SecretField,
    Session, pure,
};

/// How long one look for fields may wait (SPAs build forms after `load`).
pub(crate) const FIELD_WAIT: Duration = Duration::from_secs(10);
/// First look before trying an opener button.
const FIRST_LOOK: Duration = Duration::from_secs(3);
/// Between polls.
const POLL: Duration = Duration::from_millis(250);
/// Most opener clicks per fill.
const MAX_OPENERS: usize = 2;
/// An opener's accessible name is short ("Sign in", not a sentence).
const OPENER_NAME_MAX: usize = 40;

/// A strong username signal: used to recognise the first page of a two-step login.
const USER_STRONG: &[&str] = &[
    "input[autocomplete~=username i]:not([type=hidden])",
    "input[type=email i]",
    "input[name*=user i]:not([type=hidden]):not([type=password]), \
     input[id*=user i]:not([type=hidden]):not([type=password]), \
     input[name*=email i]:not([type=hidden]):not([type=password]), \
     input[id*=email i]:not([type=hidden]):not([type=password]), \
     input[name*=login i]:not([type=hidden]):not([type=password]), \
     input[id*=login i]:not([type=hidden]):not([type=password])",
];
/// Any username field inside a form that already has a password field.
const USER_ANY: &[&str] = &[
    "input[autocomplete~=username i]:not([type=hidden])",
    "input[type=email i]",
    "input[name*=user i]:not([type=hidden]):not([type=password]), \
     input[id*=user i]:not([type=hidden]):not([type=password]), \
     input[name*=email i]:not([type=hidden]):not([type=password]), \
     input[id*=email i]:not([type=hidden]):not([type=password]), \
     input[name*=login i]:not([type=hidden]):not([type=password]), \
     input[id*=login i]:not([type=hidden]):not([type=password])",
    "input[type=text i], input:not([type])",
];
const PASSWORD: &str = "input[type=password i]";

/// Opener words, most preferred group first.
pub(crate) const LOGIN_WORDS: &[&[&str]] = &[&["sign in", "log in", "login", "signin"]];
pub(crate) const SIGNUP_WORDS: &[&[&str]] = &[
    &[
        "sign up",
        "create account",
        "create an account",
        "register",
        "signup",
    ],
    &["sign in", "log in", "login", "signin"],
];

/// A login form as found.
#[derive(Debug)]
pub(crate) struct LoginForm {
    pub(crate) form: Option<Value>,
    pub(crate) user: Option<Value>,
    pub(crate) password: Option<Value>,
}

/// A signup form as found.
#[derive(Debug)]
pub(crate) struct SignupForm {
    /// The document root these node ids belong to.
    pub(crate) root: Value,
    pub(crate) form: Option<Value>,
    pub(crate) email: Value,
    pub(crate) name: Option<Value>,
    pub(crate) passwords: Vec<Value>,
}

/// What a step-two look found after the username was submitted.
#[derive(Debug)]
pub(crate) enum StepTwo {
    Password {
        form: Option<Value>,
        field: Value,
    },
    /// The site answered with a code field or an error instead.
    Other,
}

/// A find with one node that identifies it (for the stability check).
pub(crate) trait Keyed {
    fn key(&self) -> &Value;
}

impl Keyed for LoginForm {
    fn key(&self) -> &Value {
        self.password
            .as_ref()
            .or(self.user.as_ref())
            .unwrap_or(&Value::Null)
    }
}

impl Keyed for SignupForm {
    fn key(&self) -> &Value {
        self.passwords.first().unwrap_or(&self.email)
    }
}

impl Keyed for StepTwo {
    fn key(&self) -> &Value {
        match self {
            Self::Password { field, .. } => field,
            Self::Other => &Value::Null,
        }
    }
}

impl Keyed for (Option<Value>, Value) {
    fn key(&self) -> &Value {
        &self.1
    }
}

impl<T: Keyed> Keyed for Result<T, MapFail> {
    fn key(&self) -> &Value {
        match self {
            Ok(t) => t.key(),
            Err(_) => &Value::Null,
        }
    }
}

/// What [`Session::rehearse`] found. No values: only the form's shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormShape {
    /// Email/username first, password on the next page.
    pub two_step: bool,
    /// Visible password fields filled (new + confirm for a signup).
    pub passwords: usize,
    /// "Sign in" / "Sign up" buttons clicked to reveal the form.
    pub opener_clicks: usize,
}

/// Which form [`Session::rehearse`] maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormKind {
    /// Username + password (or the first step of a two-step login).
    Login,
    /// Email + new password (+ confirmation).
    Signup,
}

impl Session {
    /// Poll `f` until it finds a form that holds still: the same key node (by backend
    /// id, which survives re-fetching the document) on two passes in a row. Pages that
    /// render, then re-render, would otherwise hand us node ids that die mid-fill. A
    /// node vanishing mid-pass counts as "not yet". At the deadline the last pass's
    /// find (if any) is returned.
    fn poll<T: Keyed>(
        &mut self,
        limit: Duration,
        mut f: impl FnMut(&mut Self, &Value) -> Result<Option<T>, ExecError>,
    ) -> Result<Option<T>, ExecError> {
        let deadline = Instant::now() + limit;
        let mut prev: Option<u64> = None;
        loop {
            let root = self.root()?;
            let found = match f(self, &root) {
                Ok(t) => t,
                Err(ExecError::Protocol) => None,
                Err(e) => return Err(e),
            };
            // A find with no key node (an error/code page) is final as it is.
            let sig = match found.as_ref().map(Keyed::key) {
                Some(Value::Null) => return Ok(found),
                Some(k) => self.backend_id(k),
                None => None,
            };
            let done = Instant::now() >= deadline;
            if found.is_some() && (done || (sig.is_some() && sig == prev)) {
                return Ok(found);
            }
            if done {
                return Ok(None);
            }
            prev = sig;
            std::thread::sleep(POLL);
        }
    }

    /// Stable id of a node (survives `DOM.getDocument`, unlike `nodeId`).
    fn backend_id(&mut self, node: &Value) -> Option<u64> {
        let d = self
            .cdp
            .call("DOM.describeNode", json!({"nodeId": node}))
            .ok()?;
        d["node"]["backendNodeId"].as_u64()
    }

    /// Run `attempt` (map + fill, nothing submitted) again when the page swaps the
    /// nodes out from under it, up to 3 times in all.
    pub(crate) fn retry_on_stale<T>(
        &mut self,
        mut attempt: impl FnMut(&mut Self) -> Result<T, ExecError>,
    ) -> Result<T, ExecError> {
        let mut tries = 1;
        loop {
            match attempt(self) {
                Err(ExecError::Protocol) if tries < 3 => {
                    tries += 1;
                    std::thread::sleep(POLL);
                }
                r => return r,
            }
        }
    }

    /// On screen with a real size? Hidden (`display:none`) inputs have no box model;
    /// honeypots are often pushed off-screen.
    pub(crate) fn visible(&mut self, node: &Value) -> bool {
        let Ok(m) = self.cdp.call("DOM.getBoxModel", json!({"nodeId": node})) else {
            return false;
        };
        pure::box_visible(&m)
    }

    fn visible_all(&mut self, scope: &Value, sel: &str) -> Result<Vec<Value>, ExecError> {
        let all = self.query_all(scope, sel)?;
        Ok(all.into_iter().filter(|n| self.visible(n)).collect())
    }

    fn first_visible(&mut self, scope: &Value, sels: &[&str]) -> Result<Option<Value>, ExecError> {
        for sel in sels {
            if let Some(n) = self.visible_all(scope, sel)?.into_iter().next() {
                return Ok(Some(n));
            }
        }
        Ok(None)
    }

    /// The `<form>` whose inputs include `node`, if any.
    fn form_containing(&mut self, root: &Value, node: &Value) -> Result<Option<Value>, ExecError> {
        for f in self.query_all(root, "form")? {
            if self.query_all(&f, "input")?.contains(node) {
                return Ok(Some(f));
            }
        }
        Ok(None)
    }

    fn find_login(&mut self, root: &Value) -> Result<Option<LoginForm>, ExecError> {
        if let Some(pw) = self.visible_all(root, PASSWORD)?.into_iter().next() {
            let form = self.form_containing(root, &pw)?;
            let scope = form.clone().unwrap_or_else(|| root.clone());
            let user = self.first_visible(&scope, USER_ANY)?;
            return Ok(Some(LoginForm {
                form,
                user,
                password: Some(pw),
            }));
        }
        if let Some(user) = self.first_visible(root, USER_STRONG)? {
            let form = self.form_containing(root, &user)?;
            return Ok(Some(LoginForm {
                form,
                user: Some(user),
                password: None,
            }));
        }
        Ok(None)
    }

    fn find_signup(
        &mut self,
        root: &Value,
    ) -> Result<Option<Result<SignupForm, MapFail>>, ExecError> {
        let mut pws = self.visible_all(root, NEW_PW)?;
        if pws.is_empty() {
            pws = self.visible_all(root, PASSWORD)?;
        }
        let Some(first) = pws.first().cloned() else {
            return Ok(None);
        };
        let form = self.form_containing(root, &first)?;
        let scope = form.clone().unwrap_or_else(|| root.clone());
        // Every visible password field in the form: new + confirmation.
        let passwords = self.visible_all(&scope, PASSWORD)?;
        let Some(email) = self.first_visible(&scope, EMAIL_FIELDS)? else {
            return Ok(Some(Err(MapFail::NoEmailField)));
        };
        let name = self.first_visible(&scope, NAME_FIELDS)?;
        Ok(Some(Ok(SignupForm {
            root: root.clone(),
            form,
            email,
            name,
            passwords,
        })))
    }

    /// Why nothing was found: hidden-only fields, or no form at all.
    fn why_none(&mut self, sel: &str) -> MapFail {
        match self.root().and_then(|r| self.query(&r, sel)) {
            Ok(Some(_)) => MapFail::NotVisible,
            _ => MapFail::NoForm,
        }
    }

    /// Signup found nothing: hidden password fields, an email-only (passwordless)
    /// form, or nothing at all.
    fn why_no_signup(&mut self) -> MapFail {
        match self.why_none(PASSWORD) {
            MapFail::NoForm => match self
                .root()
                .and_then(|r| self.first_visible(&r, EMAIL_FIELDS))
            {
                Ok(Some(_)) => MapFail::NoPasswordField,
                _ => MapFail::NoForm,
            },
            other => other,
        }
    }

    /// Look for a form with `find`, clicking up to two same-site openers when none shows.
    fn map_with_openers<T: Keyed>(
        &mut self,
        site: &str,
        words: &[&[&str]],
        clicks: &mut usize,
        mut find: impl FnMut(&mut Self, &Value) -> Result<Option<T>, ExecError>,
    ) -> Result<Option<T>, ExecError> {
        let mut clicked = Vec::new();
        let mut waited = FIRST_LOOK;
        loop {
            if let Some(t) = self.poll(waited, &mut find)? {
                return Ok(Some(t));
            }
            if *clicks >= MAX_OPENERS {
                break;
            }
            match self.click_opener(site, words, &clicked)? {
                Some(id) => {
                    clicked.push(id);
                    *clicks += 1;
                    self.fence(site, None)?;
                    waited = FIELD_WAIT;
                }
                None => {
                    // No opener: give a slow page the rest of its time.
                    return self.poll(FIELD_WAIT.saturating_sub(FIRST_LOOK), &mut find);
                }
            }
        }
        Ok(None)
    }

    /// Map the login form (page fence first; form fence on the result).
    pub(crate) fn map_login(
        &mut self,
        site: &str,
        clicks: &mut usize,
    ) -> Result<LoginForm, ExecError> {
        self.fence(site, None)?;
        let found = self.map_with_openers(site, LOGIN_WORDS, clicks, |s, r| s.find_login(r))?;
        let Some(mut m) = found else {
            return Err(ExecError::Mapping(self.why_none(PASSWORD)));
        };
        if m.password.is_none() {
            // Only a username so far: give a progressively rendered form a moment
            // before treating it as a two-step login.
            std::thread::sleep(Duration::from_millis(500));
            if let Some(again) = self.poll(Duration::ZERO, |s, r| s.find_login(r))? {
                m = again;
            }
        }
        self.fence(site, m.form.as_ref())?;
        if m.password.is_some() && m.user.is_none() {
            return Err(ExecError::Mapping(MapFail::NoUsernameField));
        }
        Ok(m)
    }

    /// After the username step: wait for the password page (fenced), or for the site's
    /// answer (code field, error) instead.
    pub(crate) fn map_password_step(&mut self, site: &str) -> Result<StepTwo, ExecError> {
        self.fence(site, None)?;
        let found = self.poll(FIELD_WAIT, |s, root| {
            if let Some(pw) = s.visible_all(root, PASSWORD)?.into_iter().next() {
                let form = s.form_containing(root, &pw)?;
                return Ok(Some(StepTwo::Password { form, field: pw }));
            }
            if s.query(root, OTP_FIELD)?.is_some() || s.query(root, "[role=alert]")?.is_some() {
                return Ok(Some(StepTwo::Other));
            }
            Ok(None)
        })?;
        let step = found.ok_or(ExecError::Mapping(MapFail::NoPasswordField))?;
        if let StepTwo::Password { form, .. } = &step {
            self.fence(site, form.as_ref())?;
        }
        Ok(step)
    }

    /// Map the signup form (page fence first; form fence on the result).
    pub(crate) fn map_signup(
        &mut self,
        site: &str,
        clicks: &mut usize,
    ) -> Result<SignupForm, ExecError> {
        self.fence(site, None)?;
        let found = self.map_with_openers(site, SIGNUP_WORDS, clicks, |s, r| s.find_signup(r))?;
        let m = match found {
            Some(Ok(m)) => m,
            Some(Err(f)) => return Err(ExecError::Mapping(f)),
            None => return Err(ExecError::Mapping(self.why_no_signup())),
        };
        self.fence(site, m.form.as_ref())?;
        Ok(m)
    }

    /// The one-time-code field and its form (page and form fenced).
    pub(crate) fn map_code(&mut self, site: &str) -> Result<(Option<Value>, Value), ExecError> {
        self.fence(site, None)?;
        let found = self.poll(FIELD_WAIT, |s, root| {
            let Some(field) = s.visible_all(root, OTP_FIELD)?.into_iter().next() else {
                return Ok(None);
            };
            let form = s.form_containing(root, &field)?;
            Ok(Some((form, field)))
        })?;
        let (form, field) = found.ok_or(ExecError::Mapping(MapFail::NoCodeField))?;
        self.fence(site, form.as_ref())?;
        Ok((form, field))
    }

    /// Click one visible, same-site button or link whose accessible name is an opener
    /// word ("Sign in", "Create account"...). Returns its backend id, or None.
    fn click_opener(
        &mut self,
        site: &str,
        words: &[&[&str]],
        skip: &[u64],
    ) -> Result<Option<u64>, ExecError> {
        let tree = self.ax_tree()?;
        let page = self.page_url()?;
        let cands = pure::opener_candidates(&tree, words, OPENER_NAME_MAX);
        for id in cands {
            if skip.contains(&id) {
                continue;
            }
            let node = json!({"backendNodeId": id});
            let Ok(d) = self.cdp.call("DOM.describeNode", node.clone()) else {
                continue;
            };
            if let Some(href) = pure::attr(&d["node"], "href")
                && !pure::href_stays_on_site(&page, href, site)
            {
                continue;
            }
            let Ok(m) = self.cdp.call("DOM.getBoxModel", node) else {
                continue;
            };
            if !pure::box_visible(&m) {
                continue;
            }
            self.click(id)?;
            return Ok(Some(id));
        }
        Ok(None)
    }

    /// Map the login or signup form on the current page and type fixed dummy values
    /// into it, **without submitting**. For `doctor` and real-site checks: no secret is
    /// used and nothing leaves the page. A two-step login stops after the first step.
    pub fn rehearse(&mut self, site: &str, kind: FormKind) -> Result<FormShape, ExecError> {
        const DUMMY_USER: &str = "rehearsal@logindesk.invalid";
        const DUMMY_PW: &str = "rehearsal-not-a-secret";
        let mut clicks = 0;
        match kind {
            FormKind::Login => {
                let m = self.retry_on_stale(|s| {
                    let m = s.map_login(site, &mut clicks)?;
                    if let Some(u) = &m.user {
                        s.fill(u, DUMMY_USER, false)?;
                    }
                    if let Some(p) = &m.password {
                        s.fill(p, DUMMY_PW, false)?;
                    }
                    Ok(m)
                })?;
                Ok(FormShape {
                    two_step: m.password.is_none(),
                    passwords: usize::from(m.password.is_some()),
                    opener_clicks: clicks,
                })
            }
            FormKind::Signup => {
                let m = self.retry_on_stale(|s| {
                    let m = s.map_signup(site, &mut clicks)?;
                    s.fill(&m.email, DUMMY_USER, false)?;
                    for p in &m.passwords {
                        s.fill(p, DUMMY_PW, false)?;
                    }
                    Ok(m)
                })?;
                Ok(FormShape {
                    two_step: false,
                    passwords: m.passwords.len(),
                    opener_clicks: clicks,
                })
            }
        }
    }
}

/// A field the agent named by its snapshot ref, resolved and fenced.
#[derive(Debug)]
pub(crate) struct AgentField {
    /// `nodeId` in the current document.
    node: Value,
    /// `DOM.describeNode` result (`nodeName`, `attributes`).
    desc: Value,
    kind: FieldKind,
}

/// Most fields a snapshot classifies (each costs one `DOM.describeNode`).
const MAX_KINDS: usize = 400;

impl Session {
    /// Field kinds for a snapshot, by backend id, within `budget`. Fields not reached
    /// in time get no kind (their line shows only filled/empty, never a value).
    pub(crate) fn field_kinds(
        &mut self,
        tree: &Value,
        budget: Duration,
    ) -> HashMap<u64, FieldKind> {
        let deadline = Instant::now() + budget;
        let mut out = HashMap::new();
        for id in pure::field_ids(tree).into_iter().take(MAX_KINDS) {
            if Instant::now() >= deadline {
                break;
            }
            if let Ok(d) = self
                .cdp
                .call("DOM.describeNode", json!({"backendNodeId": id}))
            {
                out.insert(id, pure::field_kind(&d["node"]));
            }
        }
        out
    }

    /// Resolve a snapshot ref, and fence the page and the field's form action.
    fn agent_field(&mut self, site: &str, node_ref: u64) -> Result<AgentField, ExecError> {
        self.fence(site, None)?;
        let root = self.root()?;
        let pushed = self
            .cdp
            .call(
                "DOM.pushNodesByBackendIdsToFrontend",
                json!({"backendNodeIds": [node_ref]}),
            )
            .map_err(|_| ExecError::Mapping(MapFail::NotVisible))?;
        let node = pushed["nodeIds"][0].clone();
        if node.as_u64().is_none_or(|n| n == 0) {
            return Err(ExecError::Mapping(MapFail::NotVisible));
        }
        let d = self.cdp.call("DOM.describeNode", json!({"nodeId": node}))?;
        let desc = d["node"].clone();
        let form = self.form_of_field(&root, &node, &desc)?;
        self.fence(site, form.as_ref())?;
        Ok(AgentField {
            kind: pure::field_kind(&desc),
            node,
            desc,
        })
    }

    /// The form a field submits: its `form="id"` attribute, else the enclosing form.
    fn form_of_field(
        &mut self,
        root: &Value,
        node: &Value,
        desc: &Value,
    ) -> Result<Option<Value>, ExecError> {
        if let Some(id) = pure::attr(desc, "form") {
            let id = id.replace('\\', "\\\\").replace('"', "\\\"");
            if let Some(f) = self.query(root, &format!("form[id=\"{id}\"]"))? {
                return Ok(Some(f));
            }
        }
        for f in self.query_all(root, "form")? {
            if self
                .query_all(&f, "input, textarea, select, [contenteditable]")?
                .contains(node)
            {
                return Ok(Some(f));
            }
        }
        Ok(None)
    }

    /// `type_text`: agent text into a non-secret field; a select picks an option.
    pub(crate) fn agent_type(
        &mut self,
        site: &str,
        node_ref: u64,
        text: &str,
    ) -> Result<(), ExecError> {
        self.retry_on_stale(|s| {
            let f = s.agent_field(site, node_ref)?;
            match f.kind {
                FieldKind::Password | FieldKind::Code | FieldKind::Other => Err(ExecError::Refused),
                FieldKind::Select => s.choose_option(&f, text),
                FieldKind::TextInput | FieldKind::TextArea | FieldKind::Email => {
                    if !s.visible(&f.node) {
                        return Err(ExecError::Mapping(MapFail::NotVisible));
                    }
                    s.fill(&f.node, text, false)
                }
            }
        })
    }

    /// `fill_at`: a secret into the field this ref names, if the field suits it.
    pub(crate) fn agent_fill(
        &mut self,
        site: &str,
        node_ref: u64,
        field: SecretField,
        value: &SecretString,
    ) -> Result<(), ExecError> {
        self.retry_on_stale(|s| {
            let f = s.agent_field(site, node_ref)?;
            let ty = pure::plain_input_type(&f.desc);
            let ty = ty.as_deref();
            let suits = match field {
                SecretField::Password => f.kind == FieldKind::Password,
                SecretField::Code => {
                    f.kind == FieldKind::Code
                        || (f.kind == FieldKind::TextInput
                            && matches!(ty, Some("text" | "number" | "tel" | "")))
                }
                SecretField::Email => {
                    f.kind == FieldKind::Email
                        || (f.kind == FieldKind::TextInput && matches!(ty, Some("text" | "")))
                }
            };
            if !suits {
                return Err(ExecError::Refused);
            }
            if !s.visible(&f.node) {
                return Err(ExecError::Mapping(MapFail::NotVisible));
            }
            s.fill(&f.node, value.expose(), true)
        })
    }

    /// `press_enter_at`: Enter in the field (submits its form, which is fenced), settle.
    pub(crate) fn agent_enter(&mut self, site: &str, node_ref: u64) -> Result<(), ExecError> {
        let f = self.retry_on_stale(|s| s.agent_field(site, node_ref))?;
        self.press_enter(&f.node)?;
        self.settle(SUBMIT_LOAD)
    }

    /// Pick the `<select>` option whose label or value matches `want` (case-insensitive)
    /// by typing its label (the browser's own type-to-select, so the page sees real
    /// input/change events), then check the select shows it.
    fn choose_option(&mut self, f: &AgentField, want: &str) -> Result<(), ExecError> {
        let want = want.trim();
        let mut target = None;
        for o in self.query_all(&f.node, "option")? {
            let d = self
                .cdp
                .call("DOM.describeNode", json!({"nodeId": o, "depth": 1}))?;
            let (label, value) = pure::option_label_value(&d["node"]);
            let disabled = pure::attr(&d["node"], "disabled").is_some();
            if !disabled && (label.eq_ignore_ascii_case(want) || value.eq_ignore_ascii_case(want)) {
                target = Some(label);
                break;
            }
        }
        let label = target.ok_or(ExecError::Refused)?;
        if self.selected_label(f)?.eq_ignore_ascii_case(&label) {
            return Ok(());
        }
        // Let the previous type-to-select buffer expire, or this pick would extend it.
        if let Some(t) = self.typeahead_at {
            let gap = Duration::from_millis(1100);
            if let Some(left) = gap.checked_sub(t.elapsed()) {
                std::thread::sleep(left);
            }
        }
        self.cdp.call("DOM.focus", json!({"nodeId": f.node}))?;
        self.typeahead_at = Some(Instant::now());
        for c in label.chars() {
            self.cdp.call(
                "Input.dispatchKeyEvent",
                json!({"type": "char", "text": c.to_string()}),
            )?;
        }
        self.typeahead_at = Some(Instant::now());
        if self.selected_label(f)?.eq_ignore_ascii_case(&label) {
            Ok(())
        } else {
            Err(ExecError::Browser("select did not take the option"))
        }
    }

    /// The label a `<select>` shows now (its AX value).
    fn selected_label(&mut self, f: &AgentField) -> Result<String, ExecError> {
        let t = self.cdp.call(
            "Accessibility.getPartialAXTree",
            json!({"nodeId": f.node, "fetchRelatives": false}),
        )?;
        Ok(t["nodes"][0]["value"]["value"]
            .as_str()
            .unwrap_or("")
            .trim()
            .to_string())
    }
}
