//! Default locations and small formatting helpers.

use std::path::PathBuf;

/// `~/Library/Application Support/logindesk/vault.sqlite` on macOS,
/// `$XDG_DATA_HOME/logindesk/vault.sqlite` (or `~/.local/share/...`) elsewhere.
pub fn default_vault_path() -> Result<PathBuf, &'static str> {
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .ok_or("HOME is not set; pass --vault")?;
    let base = if cfg!(target_os = "macos") {
        PathBuf::from(home).join("Library/Application Support")
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .filter(|x| !x.is_empty())
            .map_or_else(|| PathBuf::from(&home).join(".local/share"), PathBuf::from)
    };
    Ok(base.join("logindesk").join("vault.sqlite"))
}

/// Unix seconds → `YYYY-MM-DD` (UTC). Civil-from-days, H. Hinnant.
pub fn date(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::date;

    #[test]
    fn dates() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(date(1_762_819_200), "2025-11-11");
    }
}
