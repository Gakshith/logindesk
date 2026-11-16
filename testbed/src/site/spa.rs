//! Pages that behave like real sites rather than plain HTML:
//!
//! - `/login-late`: the login form is built by JS 2 s after `load` (an SPA shell).
//! - `/login-js`: no form until the "Sign in" button is clicked; a "Sign in with
//!   Google" link to another site comes first and must not be clicked.
//! - `/login-two-step`: email, Continue, then the password on the next page
//!   (`?evil=1`: the password page posts to another origin).
//! - `/signup-late`: a signup form built by JS 2 s after `load`, with a new-password,
//!   a confirmation and an off-screen honeypot password field.
//! - `/signup-wild`: an "unpredictable" signup the agent drives field by field: first
//!   name, phone, a country select, email, password + confirm, a terms checkbox, then
//!   a code page (`?evil=1`: the form posts to another origin). The reply echoes the
//!   non-secret fields and only facts about the secret ones (lengths, a match flag).

use std::collections::HashMap;

use axum::Router;
use axum::extract::{Form, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;

use super::{Shared, esc, field, login_form, page};

/// Add these pages to the main router.
pub(super) fn routes(r: Router<Shared>) -> Router<Shared> {
    r.route("/login-late", get(login_late))
        .route("/login-js", get(login_js))
        .route("/login-two-step", get(two_step_page).post(two_step_email))
        .route("/signup-late", get(signup_late))
        .route("/signup-wild", get(wild_page).post(wild_submit))
        .route("/signup-wild/code", axum::routing::post(wild_code))
}

/// JS string literal for `html` (inserted with innerHTML).
fn js_str(html: &str) -> String {
    serde_json::to_string(html).unwrap_or_else(|_| "\"\"".into())
}

async fn login_late() -> Html<String> {
    Html(page(
        "Sign in to Example",
        &format!(
            r#"<div id="app"><p>Loading…</p></div>
<script>setTimeout(function () {{ document.getElementById('app').innerHTML = {}; }}, 2000);</script>"#,
            js_str(&login_form("/login"))
        ),
    ))
}

async fn login_js() -> Html<String> {
    Html(page(
        "Example",
        &format!(
            r#"<p><a href="https://accounts.google.example/o/oauth2">Sign in with Google</a></p>
<p>Welcome. <button type="button" id="open">Sign in</button></p>
<div id="panel"></div>
<script>
document.getElementById('open').addEventListener('click', function () {{
  setTimeout(function () {{ document.getElementById('panel').innerHTML = {}; }}, 300);
}});
</script>"#,
            js_str(&login_form("/login"))
        ),
    ))
}

fn email_step(evil: bool, alert: Option<&str>) -> String {
    let a = alert.map_or(String::new(), |m| {
        format!("<p role=\"alert\">{}</p>\n", esc(m))
    });
    let hidden = if evil {
        r#"<input type="hidden" name="evil" value="1">"#
    } else {
        ""
    };
    format!(
        r#"{a}<form method="post" action="/login-two-step">
  <label for="email">Email or mobile number</label> <input id="email" name="email" type="email" autocomplete="username">
  {hidden}<button type="submit">Continue</button>
</form>"#
    )
}

async fn two_step_page(Query(q): Query<HashMap<String, String>>) -> Html<String> {
    Html(page(
        "Sign in to Example",
        &email_step(field(&q, "evil") == "1", None),
    ))
}

async fn two_step_email(
    State(site): State<Shared>,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let email = field(&f, "email").to_string();
    let evil = field(&f, "evil") == "1";
    if !site.inner().accounts.contains_key(&email) {
        return (
            StatusCode::OK,
            Html(page(
                "Sign in to Example",
                &email_step(
                    evil,
                    Some("We cannot find an account with that email address."),
                ),
            )),
        )
            .into_response();
    }
    let action = if evil {
        format!("{}/collect?src=two-step", site.other_base())
    } else {
        "/login".to_string()
    };
    Html(page(
        "Sign in to Example",
        &format!(
            r#"<p>Signing in as {e}. <a href="/login-two-step">Change</a></p>
<form method="post" action="{a}">
  <input type="hidden" name="email" value="{e}">
  <label for="password">Password</label> <input id="password" name="password" type="password" autocomplete="current-password">
  <button type="submit">Sign in</button>
</form>"#,
            e = esc(&email),
            a = esc(&action)
        ),
    ))
    .into_response()
}

async fn signup_late() -> Html<String> {
    let form = r#"<form method="post" action="/signup">
  <label for="name">Full name</label> <input id="name" name="name" autocomplete="name">
  <label for="email">Email</label> <input id="email" name="email" type="email">
  <input type="password" name="website_pw" aria-label="Leave this empty" tabindex="-1" autocomplete="off" style="position:absolute;left:-9999px;top:0">
  <label for="password">Password</label> <input id="password" name="password" type="password" autocomplete="new-password">
  <label for="confirm">Confirm password</label> <input id="confirm" name="confirm" type="password" autocomplete="new-password">
  <button type="submit">Create account</button>
</form>"#;
    Html(page(
        "Create your Example account",
        &format!(
            r#"<div id="app"></div>
<script>setTimeout(function () {{ document.getElementById('app').innerHTML = {}; }}, 2000);</script>"#,
            js_str(form)
        ),
    ))
}

async fn wild_page(
    State(site): State<Shared>,
    Query(q): Query<HashMap<String, String>>,
) -> Html<String> {
    let action = if field(&q, "evil") == "1" {
        format!("{}/collect?src=signup-wild", site.other_base())
    } else {
        "/signup-wild".to_string()
    };
    Html(page(
        "Join Example",
        &format!(
            r#"<form method="post" action="{a}">
  <label for="fn">First name</label> <input id="fn" name="first" autocomplete="given-name">
  <label for="ph">Phone</label> <input id="ph" name="phone" type="tel">
  <label for="country">Country</label> <select id="country" name="country">
    <option value="">Choose…</option><option value="in">India</option>
    <option value="us">United States</option><option value="de">Germany</option>
  </select>
  <label for="em">Email</label> <input id="em" name="email" type="email">
  <label for="pw">Password</label> <input id="pw" name="password" type="password" autocomplete="new-password">
  <label for="pw2">Confirm password</label> <input id="pw2" name="confirm" type="password" autocomplete="new-password">
  <label><input type="checkbox" name="terms" required> I agree to the terms</label>
  <input type="hidden" name="csrf" value="t0k3n">
  <button type="submit">Create account</button>
</form>"#,
            a = esc(&action)
        ),
    ))
}

async fn wild_submit(Form(f): Form<HashMap<String, String>>) -> Html<String> {
    let (pw, confirm) = (field(&f, "password"), field(&f, "confirm"));
    let summary = format!(
        "first={}; phone={}; country={}; email={}; terms={}; password_len={}; passwords_match={}",
        field(&f, "first"),
        field(&f, "phone"),
        field(&f, "country"),
        field(&f, "email"),
        field(&f, "terms"),
        pw.chars().count(),
        if !pw.is_empty() && pw == confirm {
            "yes"
        } else {
            "no"
        },
    );
    Html(page(
        "Check your email",
        &format!(
            r#"<p role="status">{}</p>
<form method="post" action="/signup-wild/code">
  <label for="vc">Verification code</label> <input id="vc" name="code" inputmode="numeric" autocomplete="one-time-code">
  <button type="submit">Verify</button>
</form>"#,
            esc(&summary)
        ),
    ))
}

async fn wild_code(Form(f): Form<HashMap<String, String>>) -> Html<String> {
    let n = field(&f, "code")
        .chars()
        .filter(char::is_ascii_digit)
        .count();
    Html(page(
        "Welcome",
        &format!("<p role=\"status\">Code received: {n} digits</p>"),
    ))
}
