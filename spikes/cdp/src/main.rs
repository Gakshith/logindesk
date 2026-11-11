//! Phase 0 spike 2: Chrome over CDP. Throwaway code.
//! Modes:
//!   cdp oxide [--lang=xx]      chromiumoxide 0.9.1, WebSocket on a random port
//!   cdp pipe  [--lang=xx]      raw --remote-debugging-pipe client, never sends Runtime.enable
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;

mod pipe;

pub const CHROME: &str = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
pub const SECRET: &str = "spike-not-a-secret-Ünïcødé-✓";

/// Serve the static page on 127.0.0.1:<random>. Returns the URL.
pub fn serve_page() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let body = include_str!("page.html");
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        }
    });
    format!("http://127.0.0.1:{port}/")
}

pub fn fresh_profile(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("logindesk-spike-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Summarise an AX tree (as JSON from Accessibility.getFullAXTree) into lines "role | name | value".
pub fn ax_lines(tree: &serde_json::Value) -> Vec<String> {
    let mut out = vec![];
    for n in tree["nodes"].as_array().into_iter().flatten() {
        if n["ignored"].as_bool() == Some(true) {
            continue;
        }
        let role = n["role"]["value"].as_str().unwrap_or("");
        let name = n["name"]["value"].as_str().unwrap_or("");
        let value = n["value"]["value"].as_str().unwrap_or("");
        if matches!(role, "textbox" | "button" | "heading" | "StaticText" | "RootWebArea") {
            out.push(format!("{role} | {name} | {value}"));
        }
    }
    out
}

fn lang_arg() -> Vec<String> {
    std::env::args().skip(2).collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let lang = lang_arg();
    match mode.as_str() {
        "oxide" => oxide(lang.first().cloned()).await,
        "pipe" => pipe::run(lang),
        _ => {
            eprintln!("usage: cdp oxide|pipe [--lang=de]");
            Ok(())
        }
    }
}

async fn oxide(lang: Option<String>) -> anyhow::Result<()> {
    use chromiumoxide::cdp::browser_protocol::accessibility::GetFullAxTreeParams;
    use chromiumoxide::cdp::browser_protocol::input::InsertTextParams;
    use chromiumoxide::cdp::js_protocol::runtime::EventExecutionContextCreated;
    use chromiumoxide::{Browser, BrowserConfig};
    use futures::StreamExt;

    let url = serve_page();
    let profile = fresh_profile("oxide");
    let mut cfg = BrowserConfig::builder()
        .chrome_executable(CHROME)
        .with_head()
        .user_data_dir(&profile)
        .viewport(None);
    if let Some(l) = &lang {
        cfg = cfg.arg(l.trim_start_matches("--"));
    }
    let (mut browser, mut handler) = Browser::launch(cfg.build().map_err(anyhow::Error::msg)?).await?;
    eprintln!("[oxide] ws url: {}", browser.websocket_address());
    let h = tokio::spawn(async move { while let Some(_e) = handler.next().await {} });

    let page = browser.new_page("about:blank").await?;
    let mut ctx_events = page.event_listener::<EventExecutionContextCreated>().await?;
    page.goto(url.as_str()).await?;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let mut ctx_count = 0;
    while let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(50), ctx_events.next()).await {
        ctx_count += 1;
    }
    eprintln!("[oxide] Runtime.executionContextCreated events seen: {ctx_count} (>0 means Runtime.enable is on)");

    let tree = page.execute(GetFullAxTreeParams::default()).await?;
    let tree = serde_json::to_value(&tree.result)?;
    eprintln!("[oxide] AX nodes: {}", tree["nodes"].as_array().map(|a| a.len()).unwrap_or(0));
    for l in ax_lines(&tree) {
        eprintln!("[oxide]   {l}");
    }

    page.find_element("#pw").await?.focus().await?;
    page.execute(InsertTextParams::new(SECRET)).await?;
    let tree = serde_json::to_value(&page.execute(GetFullAxTreeParams::default()).await?.result)?;
    let pw = page.find_element("#pw").await?.property("value").await?;
    eprintln!("[oxide] after Input.insertText: #pw.value == SECRET ? {}", pw.as_ref().and_then(|v| v.as_str()) == Some(SECRET));
    for l in ax_lines(&tree).into_iter().filter(|l| l.starts_with("textbox")) {
        eprintln!("[oxide]   {l}");
    }
    let shot = profile.join("oxide.png");
    page.save_screenshot(chromiumoxide::page::ScreenshotParams::builder().build(), &shot).await?;
    eprintln!("[oxide] screenshot: {}", shot.display());

    browser.close().await?;
    let _ = browser.wait().await;
    h.abort();
    Ok(())
}
