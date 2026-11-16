//! Import without duplicates, and `vault dedupe`.
//!
//! Two login records are the same account when their registrable domain and
//! username match (the username trimmed, case kept: some sites treat case as
//! distinct). Secrets are compared inside this process and never printed.

use std::collections::HashMap;

use logindesk_core::SecretString;
use logindesk_policy::site_of;
use logindesk_vault::{ImportRow, Keys, NewRecord, RecordId, RecordKind, RecordMeta, Result, Vault};

/// (registrable domain or the trimmed lowercase site, trimmed username).
pub type Key = (String, String);

/// The account key of a site + username.
pub fn key(site: &str, username: &str) -> Key {
    let s = site_of(site).unwrap_or_else(|| site.trim().to_ascii_lowercase());
    (s, username.trim().to_string())
}

/// What an import did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ImportCounts {
    /// New records.
    pub imported: usize,
    /// Existing records whose password changed.
    pub updated: usize,
    /// Rows already in the vault with the same password.
    pub skipped: usize,
}

/// Import `rows`, skipping any (site, username) already stored. A row whose
/// password differs from the stored one updates it. Duplicate rows inside the
/// CSV are handled the same way (the later row wins).
pub fn import(vault: &mut Vault, keys: &Keys, rows: Vec<ImportRow>) -> Result<ImportCounts> {
    let mut have: HashMap<Key, (RecordId, SecretString)> = HashMap::new();
    for r in vault.records(keys)? {
        if r.meta.kind == RecordKind::Login {
            have.insert(key(&r.meta.site, &r.meta.username), (r.meta.id, r.secret));
        }
    }
    let mut c = ImportCounts::default();
    for row in rows {
        let k = key(&row.site, &row.username);
        match have.get_mut(&k) {
            Some((_, old)) if old.expose() == row.secret.expose() => c.skipped += 1,
            Some((id, old)) => {
                *old = SecretString::new(row.secret.expose().clone());
                vault.update_secret(keys, *id, row.secret)?;
                c.updated += 1;
            }
            None => {
                let copy = SecretString::new(row.secret.expose().clone());
                let id = vault.add(
                    keys,
                    NewRecord {
                        kind: RecordKind::Login,
                        site: row.site,
                        username: row.username,
                        secret: row.secret,
                        created_by: "import:csv".into(),
                        notes: row.notes,
                    },
                )?;
                have.insert(k, (id, copy));
                c.imported += 1;
            }
        }
    }
    Ok(c)
}

/// Login records that duplicate a newer one: for each (site, username) with
/// more than one record, every record but the newest (by `updated_at`, then
/// `created_at`, then version).
pub fn duplicates(metas: &[RecordMeta]) -> Vec<&RecordMeta> {
    let mut groups: HashMap<Key, Vec<&RecordMeta>> = HashMap::new();
    for m in metas.iter().filter(|m| m.kind == RecordKind::Login) {
        groups.entry(key(&m.site, &m.username)).or_default().push(m);
    }
    let mut out: Vec<&RecordMeta> = Vec::new();
    for mut g in groups.into_values().filter(|g| g.len() > 1) {
        g.sort_by_key(|m| (m.updated_at, m.created_at, m.version));
        g.pop(); // the newest stays
        out.extend(g);
    }
    out.sort_by(|a, b| (&a.site, &a.username).cmp(&(&b.site, &b.username)));
    out
}

/// Delete every duplicate, keeping the newest of each account. Returns what was removed.
pub fn dedupe(vault: &mut Vault, keys: &Keys) -> Result<Vec<RecordMeta>> {
    let metas = vault.list(keys)?;
    let gone: Vec<RecordMeta> = duplicates(&metas).into_iter().cloned().collect();
    for m in &gone {
        vault.delete(keys, m.id)?;
    }
    Ok(gone)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_match_on_registrable_domain() {
        assert_eq!(
            key("https://www.amazon.com/ap/signin", " ann@x.com "),
            key("amazon.com", "ann@x.com")
        );
        assert_ne!(key("amazon.com", "Ann"), key("amazon.com", "ann"));
        assert_ne!(key("amazon.com", "ann"), key("amazon.co.uk", "ann"));
        assert_eq!(key("not a site", "a").0, "not a site");
    }
}
