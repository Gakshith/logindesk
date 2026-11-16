//! `logindesk install|uninstall --client X`: add or remove our MCP server entry in a
//! client's config file.
//!
//! Rules: the entry holds the absolute path of the running binary; re-running is a
//! no-op; the file is backed up (`<file>.bak-<unix time>`) before any write; no other
//! entry is touched; `--dry-run` prints the change and writes nothing.
//!
//! JSON files are rewritten through `serde_json`, so key order is normalised (sorted)
//! on a real change; the backup keeps the original bytes.

use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};

/// Our entry's name in every client.
pub const NAME: &str = "logindesk";

/// A supported MCP client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Client {
    /// Claude Code (`claude mcp add --scope user`, else `~/.claude.json`).
    ClaudeCode,
    /// Claude Desktop (`claude_desktop_config.json`).
    ClaudeDesktop,
    /// Cursor (`~/.cursor/mcp.json`).
    Cursor,
    /// VS Code (user-profile `mcp.json`).
    Vscode,
    /// Codex CLI (`~/.codex/config.toml`).
    Codex,
    /// Gemini CLI (`~/.gemini/settings.json`).
    Gemini,
}

impl Client {
    /// Every client, for `doctor`.
    pub const ALL: [Self; 6] = [
        Self::ClaudeCode,
        Self::ClaudeDesktop,
        Self::Cursor,
        Self::Vscode,
        Self::Codex,
        Self::Gemini,
    ];

    /// Human name.
    pub fn label(self) -> &'static str {
        match self {
            Self::ClaudeCode => "Claude Code",
            Self::ClaudeDesktop => "Claude Desktop",
            Self::Cursor => "Cursor",
            Self::Vscode => "VS Code",
            Self::Codex => "Codex",
            Self::Gemini => "Gemini CLI",
        }
    }

    /// The config file under `home`.
    pub fn config_path(self, home: &Path) -> PathBuf {
        let mac = cfg!(target_os = "macos");
        match self {
            Self::ClaudeCode => home.join(".claude.json"),
            Self::ClaudeDesktop if mac => {
                home.join("Library/Application Support/Claude/claude_desktop_config.json")
            }
            Self::ClaudeDesktop => home.join(".config/Claude/claude_desktop_config.json"),
            Self::Cursor => home.join(".cursor/mcp.json"),
            Self::Vscode if mac => home.join("Library/Application Support/Code/User/mcp.json"),
            Self::Vscode => home.join(".config/Code/User/mcp.json"),
            Self::Codex => home.join(".codex/config.toml"),
            Self::Gemini => home.join(".gemini/settings.json"),
        }
    }

    /// JSON object that holds the servers (`None` for the TOML client).
    fn container(self) -> Option<&'static str> {
        match self {
            Self::Vscode => Some("servers"),
            Self::Codex => None,
            _ => Some("mcpServers"),
        }
    }
}

/// What the entry launches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Absolute path of the `logindesk` binary.
    pub command: PathBuf,
    /// `["mcp"]`.
    pub args: Vec<String>,
    /// `LOGINDESK_VAULT`, when the user set one.
    pub env: Vec<(String, String)>,
}

impl Entry {
    /// The running binary + `mcp`, plus `LOGINDESK_VAULT` when `vault` is given.
    pub fn current(vault: Option<&Path>) -> io::Result<Self> {
        let exe = std::env::current_exe()?;
        let command = exe.canonicalize().unwrap_or(exe);
        let mut env = Vec::new();
        if let Some(v) = vault {
            let abs = if v.is_absolute() {
                v.to_path_buf()
            } else {
                std::env::current_dir()?.join(v)
            };
            env.push(("LOGINDESK_VAULT".into(), abs.display().to_string()));
        }
        Ok(Self {
            command,
            args: vec!["mcp".into()],
            env,
        })
    }

    fn json(&self, client: Client) -> Value {
        let env: Map<String, Value> = self
            .env
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        let mut e = json!({
            "command": self.command.display().to_string(),
            "args": self.args,
            "env": env,
        });
        if matches!(client, Client::Vscode | Client::ClaudeCode) {
            e["type"] = json!("stdio");
        }
        e
    }

    fn toml(&self) -> String {
        let args: Vec<String> = self.args.iter().map(|a| toml_str(a)).collect();
        let mut s = format!(
            "[mcp_servers.{NAME}]\ncommand = {}\nargs = [{}]\n",
            toml_str(&self.command.display().to_string()),
            args.join(", ")
        );
        if !self.env.is_empty() {
            let kv: Vec<String> = self
                .env
                .iter()
                .map(|(k, v)| format!("{k} = {}", toml_str(v)))
                .collect();
            let _ = writeln!(s, "env = {{ {} }}", kv.join(", "));
        }
        s
    }
}

/// TOML basic string.
fn toml_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\t' => o.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(o, "\\u{:04X}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// What happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Already as wanted; nothing written.
    Unchanged,
    /// Written (backup path, if a file existed).
    Written(Option<PathBuf>),
    /// Dry run: this is the diff that would apply.
    WouldWrite(String),
    /// Ran `claude mcp ...` (backup path, if a file existed).
    RanClaudeCli(Option<PathBuf>),
    /// Dry run of the Claude Code CLI path.
    WouldRun(Vec<String>),
}

/// `claude` on PATH, if any.
fn claude_cli() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join("claude"))
        .find(|p| p.is_file())
}

/// Install (or update) our entry.
pub fn install(client: Client, home: &Path, entry: &Entry, dry_run: bool) -> io::Result<Outcome> {
    apply(client, home, Some(entry), dry_run)
}

/// Remove our entry; other entries stay.
pub fn uninstall(client: Client, home: &Path, dry_run: bool) -> io::Result<Outcome> {
    apply(client, home, None, dry_run)
}

fn apply(client: Client, home: &Path, entry: Option<&Entry>, dry_run: bool) -> io::Result<Outcome> {
    let path = client.config_path(home);
    let old = match std::fs::read_to_string(&path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let (before, after) = match client.container() {
        Some(key) => json_edit(client, key, old.as_deref(), entry, &path)?,
        None => {
            let b = old.clone().unwrap_or_default();
            let a = toml_edit(&b, entry);
            (b, a)
        }
    };
    if before == after {
        return Ok(Outcome::Unchanged);
    }
    if client == Client::ClaudeCode
        && let Some(claude) = claude_cli()
    {
        return run_claude(&claude, &path, old.is_some(), entry, dry_run);
    }
    if dry_run {
        return Ok(Outcome::WouldWrite(diff(&path, &before, &after)));
    }
    let backup = match old {
        Some(_) => Some(backup(&path)?),
        None => None,
    };
    write_atomic(&path, &after)?;
    Ok(Outcome::Written(backup))
}

/// Canonical JSON before and after the edit. Refuses a file that is not a JSON object.
fn json_edit(
    client: Client,
    key: &str,
    old: Option<&str>,
    entry: Option<&Entry>,
    path: &Path,
) -> io::Result<(String, String)> {
    let mut root: Value = match old.map(str::trim) {
        None | Some("") => json!({}),
        Some(s) => serde_json::from_str(s).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} is not valid JSON ({e}); fix or move it first",
                    path.display()
                ),
            )
        })?,
    };
    if !root.is_object() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} is not a JSON object; fix or move it first",
                path.display()
            ),
        ));
    }
    let before = pretty(&root)?;
    match entry {
        Some(e) => {
            let servers = root
                .as_object_mut()
                .map(|m| m.entry(key).or_insert_with(|| json!({})))
                .filter(|v| v.is_object())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("\"{key}\" in {} is not an object", path.display()),
                    )
                })?;
            servers[NAME] = e.json(client);
        }
        None => {
            if let Some(m) = root.get_mut(key).and_then(Value::as_object_mut) {
                m.remove(NAME);
            }
        }
    }
    Ok((before, pretty(&root)?))
}

fn pretty(v: &Value) -> io::Result<String> {
    let mut s = serde_json::to_string_pretty(v).map_err(io::Error::other)?;
    s.push('\n');
    Ok(s)
}

/// Is this line a TOML table header naming our server (or one of its sub-tables)?
fn header_key(line: &str) -> Option<String> {
    let t = line.split('#').next().unwrap_or("").trim();
    let inner = t.strip_prefix('[')?.strip_suffix(']')?;
    let inner = inner.trim_start_matches('[').trim_end_matches(']');
    let ok = inner
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_-.\"' ".contains(c));
    ok.then(|| inner.chars().filter(|c| !"\"' ".contains(*c)).collect())
}

fn is_ours(key: &str) -> bool {
    let me = format!("mcp_servers.{NAME}");
    key == me || key.starts_with(&format!("{me}."))
}

/// Our `[mcp_servers.logindesk]` table (and its sub-tables) removed, then the new one
/// appended. Everything else is kept byte for byte.
fn toml_edit(old: &str, entry: Option<&Entry>) -> String {
    let mut kept = String::new();
    let mut skipping = false;
    for line in old.split_inclusive('\n') {
        if let Some(k) = header_key(line) {
            skipping = is_ours(&k);
        }
        if !skipping {
            kept.push_str(line);
        }
    }
    let Some(e) = entry else { return kept };
    let mut out = kept.trim_end().to_string();
    if !out.is_empty() {
        out.push_str("\n\n");
    }
    out.push_str(&e.toml());
    // Re-running must be a no-op: if the file already ended with exactly our table, keep it.
    if old.trim_end() == out.trim_end() {
        return old.to_string();
    }
    out
}

fn run_claude(
    claude: &Path,
    file: &Path,
    file_exists: bool,
    entry: Option<&Entry>,
    dry_run: bool,
) -> io::Result<Outcome> {
    let remove: Vec<String> = ["mcp", "remove", "--scope", "user", NAME]
        .map(String::from)
        .to_vec();
    let add = entry.map(|e| {
        // Name before `-e`: `-e` is variadic and would swallow it.
        let mut a: Vec<String> = ["mcp", "add", "--scope", "user", NAME]
            .map(String::from)
            .to_vec();
        for (k, v) in &e.env {
            a.push("-e".into());
            a.push(format!("{k}={v}"));
        }
        a.push("--".into());
        a.push(e.command.display().to_string());
        a.extend(e.args.iter().cloned());
        a
    });
    let show = |args: &[String]| format!("{} {}", claude.display(), args.join(" "));
    if dry_run {
        let mut cmds = vec![show(&remove)];
        cmds.extend(add.as_deref().map(show));
        return Ok(Outcome::WouldRun(cmds));
    }
    let backup = if file_exists {
        Some(backup(file)?)
    } else {
        None
    };
    // `remove` fails when there is nothing to remove; that is fine.
    let _ = Command::new(claude)
        .args(&remove)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    if let Some(a) = add {
        let st = Command::new(claude)
            .args(&a)
            .stdout(std::process::Stdio::null())
            .status()?;
        if !st.success() {
            return Err(io::Error::other(format!("`{}` failed", show(&a))));
        }
    }
    Ok(Outcome::RanClaudeCli(backup))
}

/// Copy `path` to `path.bak-<unix time>` (with a counter if that exists). Keeps its mode.
fn backup(path: &Path) -> io::Result<PathBuf> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let base = format!("{}.bak-{ts}", path.display());
    let mut b = PathBuf::from(&base);
    let mut n = 1;
    while b.exists() {
        b = PathBuf::from(format!("{base}-{n}"));
        n += 1;
    }
    std::fs::copy(path, &b)?;
    Ok(b)
}

/// Write via a temp file + rename, keeping the old file's mode (0600 for a new file).
fn write_atomic(path: &Path, text: &str) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let mode = std::fs::metadata(path).map_or(0o600, |m| m.permissions().mode() & 0o777);
    let name = path.file_name().map_or_else(
        || "config".to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let tmp = dir.join(format!(".{name}.logindesk-tmp"));
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(tmp, path)
}

/// A unified-style diff of the changed middle (files differ in one region).
fn diff(path: &Path, before: &str, after: &str) -> String {
    let a: Vec<&str> = before.lines().collect();
    let b: Vec<&str> = after.lines().collect();
    let pre = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let suf = a[pre..]
        .iter()
        .rev()
        .zip(b[pre..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let mut o = format!(
        "--- {p}\n+++ {p}\n@@ line {} @@\n",
        pre + 1,
        p = path.display()
    );
    let ctx = pre.saturating_sub(2);
    for l in &a[ctx..pre] {
        let _ = writeln!(o, " {l}");
    }
    for l in &a[pre..a.len() - suf] {
        let _ = writeln!(o, "-{l}");
    }
    for l in &b[pre..b.len() - suf] {
        let _ = writeln!(o, "+{l}");
    }
    for l in a[a.len() - suf..].iter().take(2) {
        let _ = writeln!(o, " {l}");
    }
    o
}

/// `logindesk install` / `uninstall`: human messages on stderr, a dry-run diff on stdout.
pub fn cmd(
    client: Client,
    vault: Option<&Path>,
    remove: bool,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .ok_or("HOME is not set")?;
    let path = client.config_path(&home);
    let out = if remove {
        uninstall(client, &home, dry_run)?
    } else {
        install(client, &home, &Entry::current(vault)?, dry_run)?
    };
    let what = if remove {
        "removed from"
    } else {
        "installed in"
    };
    match out {
        Outcome::Unchanged if remove => {
            eprintln!(
                "{}: logindesk is not in {}.",
                client.label(),
                path.display()
            );
        }
        Outcome::Unchanged => {
            eprintln!(
                "{}: already up to date in {}.",
                client.label(),
                path.display()
            );
        }
        Outcome::Written(b) | Outcome::RanClaudeCli(b) => {
            eprintln!("{}: logindesk {what} {}.", client.label(), path.display());
            if let Some(b) = b {
                eprintln!("Backup: {}", b.display());
            }
            eprintln!("Restart {} to pick up the change.", client.label());
        }
        Outcome::WouldWrite(d) => {
            std::io::Write::write_all(&mut std::io::stdout().lock(), d.as_bytes())?;
            eprintln!("Dry run: nothing written.");
        }
        Outcome::WouldRun(cmds) => {
            let mut out = std::io::stdout().lock();
            for c in cmds {
                std::io::Write::write_all(&mut out, format!("{c}\n").as_bytes())?;
            }
            eprintln!(
                "Dry run: would run the commands above (backing up {} first).",
                path.display()
            );
        }
    }
    Ok(())
}

/// The `command` our entry in `client`'s config points to, if there is an entry.
pub fn installed_command(client: Client, home: &Path) -> io::Result<Option<String>> {
    let text = match std::fs::read_to_string(client.config_path(home)) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    match client.container() {
        Some(key) => {
            let v: Value = serde_json::from_str(&text)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Ok(v[key][NAME]["command"].as_str().map(str::to_string))
        }
        None => {
            let mut ours = false;
            for line in text.lines() {
                if let Some(k) = header_key(line) {
                    ours = k == format!("mcp_servers.{NAME}");
                } else if ours
                    && let Some(rest) = line.trim().strip_prefix("command")
                    && let Some(v) = rest.trim().strip_prefix('=')
                {
                    return Ok(Some(toml_unquote(v.trim())));
                }
            }
            Ok(None)
        }
    }
}

fn toml_unquote(s: &str) -> String {
    let s = s.split(" #").next().unwrap_or(s).trim();
    if let Some(i) = s.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')) {
        return i.to_string();
    }
    serde_json::from_str::<String>(s).unwrap_or_else(|_| s.trim_matches('"').to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn entry() -> Entry {
        Entry {
            command: PathBuf::from("/opt/ld/bin/logindesk"),
            args: vec!["mcp".into()],
            env: vec![("LOGINDESK_VAULT".into(), "/v/vault.sqlite".into())],
        }
    }

    #[test]
    fn toml_add_replace_remove() {
        let user =
            "model = \"o3\"\n\n[mcp_servers.other]\ncommand = \"x\"\nargs = [\n  \"a\",\n]\n";
        let once = toml_edit(user, Some(&entry()));
        assert!(once.starts_with(user.trim_end()));
        assert!(once.contains("[mcp_servers.logindesk]\ncommand = \"/opt/ld/bin/logindesk\"\nargs = [\"mcp\"]\nenv = { LOGINDESK_VAULT = \"/v/vault.sqlite\" }\n"));
        assert_eq!(toml_edit(&once, Some(&entry())), once, "idempotent");
        // A hand-edited sub-table of ours is replaced too; tables after ours are kept.
        let messy = format!("{once}[mcp_servers.logindesk.env]\nX = \"1\"\n\n[tail]\nk = 1\n");
        let fixed = toml_edit(&messy, Some(&entry()));
        assert!(fixed.contains("[tail]\nk = 1"));
        assert_eq!(fixed.matches("logindesk]").count(), 1);
        assert!(!fixed.contains("X = \"1\""));
        let gone = toml_edit(&fixed, None);
        assert!(!gone.contains("logindesk"));
        assert!(gone.contains("[mcp_servers.other]") && gone.contains("[tail]"));
    }

    #[test]
    fn toml_strings_escape() {
        assert_eq!(toml_str(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(toml_unquote(r#""a\"b\\c""#), r#"a"b\c"#);
        assert_eq!(toml_unquote("'/x y'"), "/x y");
    }

    #[test]
    fn json_refuses_non_object() {
        let p = Path::new("/x.json");
        assert!(json_edit(Client::Cursor, "mcpServers", Some("[1]"), Some(&entry()), p).is_err());
        assert!(json_edit(Client::Cursor, "mcpServers", Some("{"), Some(&entry()), p).is_err());
        assert!(
            json_edit(
                Client::Cursor,
                "mcpServers",
                Some(r#"{"mcpServers": 3}"#),
                Some(&entry()),
                p
            )
            .is_err()
        );
    }

    #[test]
    fn diff_shows_only_the_change() {
        let d = diff(Path::new("f"), "a\nb\nc\nd\n", "a\nb\nX\nd\n");
        assert!(d.contains("-c\n+X\n"));
        assert!(d.contains(" b\n") && d.contains(" d\n"));
    }
}
