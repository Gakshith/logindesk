//! CSV import (from browser / password-manager exports) and the opt-in
//! plaintext CSV export.
//!
//! Limitation: the `csv` crate's internal buffers are not zeroized, so a
//! plaintext secret can linger in freed heap memory after an import or a
//! plaintext export. Both are rare, user-initiated, local operations; the
//! CSV file on disk is the bigger exposure and the CLI warns about it.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use logindesk_core::SecretString;

use crate::error::{Error, Result};
use crate::format::{MAX_FIELD_LEN, MAX_RECORDS};
use crate::record::Record;

/// One row from an import CSV.
#[derive(Debug)]
pub struct ImportRow {
    /// Site or URL as written in the CSV.
    pub site: String,
    /// Username (may be empty).
    pub username: String,
    /// Password.
    pub secret: SecretString,
    /// Notes (may be empty).
    pub notes: String,
}

const SITE: &[&str] = &["site", "url", "login_uri", "website", "origin"];
const USERNAME: &[&str] = &["username", "login_username", "user", "email", "login"];
const PASSWORD: &[&str] = &["password", "login_password"];
const NOTES: &[&str] = &["notes", "note", "extra", "comments"];

fn column(headers: &[String], names: &[&str]) -> Option<usize> {
    names
        .iter()
        .find_map(|n| headers.iter().position(|h| h == n))
}

fn csv_err(e: &csv::Error, reason: &'static str) -> Error {
    Error::Csv {
        line: e.position().map(csv::Position::line),
        reason,
    }
}

/// Parses an import CSV. The header row is required; columns are matched by
/// name, case-insensitively (Chrome, Firefox, Safari, Bitwarden and
/// 1Password exports all work). `site` and `password` are required.
/// Error messages carry a line number, never cell content.
pub fn parse_import_csv<R: Read>(input: R) -> Result<Vec<ImportRow>> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(false)
        .from_reader(input);
    let headers: Vec<String> = rdr
        .byte_headers()
        .map_err(|e| csv_err(&e, "malformed header row"))?
        .iter()
        .map(|h| {
            String::from_utf8_lossy(h)
                .trim()
                .trim_start_matches('\u{feff}')
                .to_ascii_lowercase()
        })
        .collect();
    let site_col = column(&headers, SITE).ok_or(Error::Csv {
        line: Some(1),
        reason: "no site or url column",
    })?;
    let pass_col = column(&headers, PASSWORD).ok_or(Error::Csv {
        line: Some(1),
        reason: "no password column",
    })?;
    let user_col = column(&headers, USERNAME);
    let notes_col = column(&headers, NOTES);

    let mut rows = Vec::new();
    let mut rec = csv::ByteRecord::new();
    loop {
        match rdr.read_byte_record(&mut rec) {
            Ok(false) => break,
            Ok(true) => {}
            Err(e) => return Err(csv_err(&e, "malformed row")),
        }
        let line = rec.position().map(csv::Position::line);
        let field = |col: Option<usize>| -> Result<String> {
            let raw = col.and_then(|c| rec.get(c)).unwrap_or(b"");
            if raw.len() > MAX_FIELD_LEN {
                return Err(Error::Csv {
                    line,
                    reason: "a field is longer than 64 KiB",
                });
            }
            String::from_utf8(raw.to_vec()).map_err(|_| Error::Csv {
                line,
                reason: "a field is not UTF-8",
            })
        };
        let site = field(Some(site_col))?.trim().to_owned();
        let secret = SecretString::new(field(Some(pass_col))?);
        if site.is_empty() {
            return Err(Error::Csv {
                line,
                reason: "empty site",
            });
        }
        if secret.expose().is_empty() {
            return Err(Error::Csv {
                line,
                reason: "empty password",
            });
        }
        if rows.len() >= MAX_RECORDS {
            return Err(Error::Csv {
                line,
                reason: "too many rows",
            });
        }
        rows.push(ImportRow {
            site,
            username: field(user_col)?.trim().to_owned(),
            secret,
            notes: field(notes_col)?,
        });
    }
    Ok(rows)
}

/// Writes records, **including their secrets in plaintext**, to a new CSV
/// file created with mode 0600. Refuses to overwrite an existing file.
/// Columns: `site,username,password,kind,notes,created_by`.
pub fn write_plaintext_csv(path: &Path, records: &[Record]) -> Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Error::AlreadyExists
            } else {
                Error::Io(e)
            }
        })?;
    let mut w = csv::Writer::from_writer(file);
    let werr = |e: csv::Error| csv_err(&e, "write failed");
    w.write_record([
        "site",
        "username",
        "password",
        "kind",
        "notes",
        "created_by",
    ])
    .map_err(werr)?;
    for r in records {
        let m = &r.meta;
        w.write_record([
            m.site.as_str(),
            &m.username,
            r.secret.expose(),
            m.kind.name(),
            &m.notes,
            &m.created_by,
        ])
        .map_err(werr)?;
    }
    let mut file = w.into_inner().map_err(|e| Error::Io(e.into_error()))?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_export_columns_parse() {
        let csv =
            "name,url,username,password,note\nEx,https://example.test/login,alice,CANARY-pw-1,hi\n";
        let rows = parse_import_csv(csv.as_bytes()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].site, "https://example.test/login");
        assert_eq!(rows[0].username, "alice");
        assert_eq!(rows[0].secret.expose(), "CANARY-pw-1");
        assert_eq!(rows[0].notes, "hi");
    }

    #[test]
    fn bitwarden_columns_and_bom_parse() {
        let csv = "\u{feff}folder,type,name,login_uri,login_username,login_password\n,login,x,example.test,bob,CANARY-pw-2\n";
        let rows = parse_import_csv(csv.as_bytes()).unwrap();
        assert_eq!(rows[0].site, "example.test");
        assert_eq!(rows[0].username, "bob");
    }

    #[test]
    fn errors_name_the_line_but_never_the_content() {
        let csv = "url,password\nexample.test,\n";
        let err = parse_import_csv(csv.as_bytes()).unwrap_err().to_string();
        assert!(err.contains("line 2"), "{err}");
        let csv = "url,password\nexample.test,CANARY-pw-3,extra-column\n";
        let err = parse_import_csv(csv.as_bytes()).unwrap_err().to_string();
        assert!(!err.contains("CANARY"), "{err}");
    }

    #[test]
    fn missing_columns_are_rejected() {
        assert!(parse_import_csv("url,username\nx,y\n".as_bytes()).is_err());
        assert!(parse_import_csv("username,password\nx,y\n".as_bytes()).is_err());
    }
}
