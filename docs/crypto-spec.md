# Vault crypto specification (format v1)

Status: logindesk 0.1, Phase 2. Code: `crates/vault`. Not externally audited.

## Summary

| Purpose | Primitive | Crate (pinned) |
|---|---|---|
| Password → master key | Argon2id v1.3 | `argon2 =0.6.0` |
| Master key → subkeys | HKDF-SHA256 | `hkdf =0.13.0`, `sha2 =0.11.1` |
| Encryption | XChaCha20-Poly1305 (24-byte random nonces) | `chacha20poly1305 =0.11.0` |
| Randomness | OS RNG (`getrandom`) | `getrandom =0.4.3` |
| Storage | SQLite, bundled | `rusqlite =0.42.0` |

No custom primitives. Every primitive has a known-answer test against a published vector:

| Test | Vector |
|---|---|
| `crypto::tests::xchacha20poly1305_kat_draft_irtf_cfrg_xchacha_03_a_3_1` | draft-irtf-cfrg-xchacha-03, Appendix A.3.1 |
| `keys::tests::argon2id_kat_rfc9106_5_3` | RFC 9106 §5.3 (Argon2id) |
| `keys::tests::hkdf_sha256_kat_rfc5869_a_1` | RFC 5869 Appendix A.1 (Test Case 1) |

## Keys

```text
master   = Argon2id(password, salt[32], m, t, p, out = 32 bytes)
PRK      = HKDF-Extract(salt = "logindesk/v1", IKM = master)
KEK      = HKDF-Expand(PRK, "logindesk/v1/kek", 32)
K_check  = HKDF-Expand(PRK, "logindesk/v1/key-check", 32)
K_man    = HKDF-Expand(PRK, "logindesk/v1/manifest", 32)
DEK_i    = 32 random bytes, fresh for every write of every record
```

- The master key and all subkeys live in one page-aligned heap page that is `mlock`ed. The page is owned exclusively, zeroized before it is freed, then `munlock`ed. The master key is zeroized as soon as HKDF-Extract has consumed it.
- Dropping `Keys` locks the vault. `VaultSession` drops them after **15 minutes idle**. Idle time is the larger of monotonic time and wall-clock time, because macOS's monotonic clock stops during sleep.
- Argon2id's working memory is zeroized by the `argon2` crate (`zeroize` feature).

## Argon2id parameters

Parameters are stored per vault in the header, so they can be raised later without breaking old vaults.

| | m | t | p |
|---|---|---|---|
| **Default for new vaults** | **512 MiB (524288 KiB)** | **3** | **1** |
| Minimum accepted (any vault) | 19 MiB (19456 KiB) | 2 | 1 |
| Maximum accepted (header sanity) | 4 GiB | 64 | 16 |

**OWASP check (2026-11-11).** The OWASP Password Storage Cheat Sheet, fetched 2026-11-11, gives these Argon2id minimums:
- m=47104 (46 MiB), t=1, p=1
- m=19456 (19 MiB), t=2, p=1
- m=12288 (12 MiB), t=3, p=1
- m=9216 (9 MiB), t=4, p=1
- m=7168 (7 MiB), t=5, p=1

The cheat sheet treats these as equivalent.
- The default (512 MiB, t=3) uses about 27× the memory of the m=19456, t=2 row and more passes, so it is well above every row.
- The accepted minimum equals the m=19456, t=2 row. A vault whose header asks for less is refused as `Unsupported`, and so is a header that claims an equivalent row with t<2.
- p=1 because the `argon2` crate runs lanes sequentially without its `parallel` feature, so more lanes would add time with no benefit.

**Measured unlock time.** These are `cargo run --release -p logindesk-vault --example tune_kdf` results, measuring the full `Vault::unlock` (Argon2id, HKDF and key check). The Mac is an Apple M1 with 8 GB, on 2026-11-11.

| m (MiB) | t | p | min | median | max |
|---|---|---|---|---|---|
| 128 | 3 | 1 | 0.173 s | 0.177 s | 0.179 s |
| 256 | 2 | 1 | 0.241 s | 0.243 s | 0.244 s |
| 256 | 4 | 1 | 0.485 s | 0.487 s | 0.555 s |
| 256 | 6 | 1 | 0.730 s | 0.737 s | 0.793 s |
| 384 | 4 | 1 | 0.741 s | 0.743 s | 0.748 s |
| 512 | 2 | 1 | 0.501 s | 0.505 s | 0.539 s |
| **512** | **3** | **1** | **0.748 s** | **0.753 s** | **0.869 s** |
| 512 | 4 | 1 | 1.025 s | 1.030 s | 1.311 s |

Five unlocks per row, measured with nothing else running.

**Why 512 MiB, t=3:**
- It is the most memory-hard setting inside the target window, and memory is what slows down GPU and ASIC cracking.
- The M1 is the slowest M-series chip, so newer Macs land lower in the window.
- 256 MiB at t=2 (0.24 s) was rejected as too fast.
- An earlier run taken while a fuzzer used a core showed 0.81 s for 256 MiB at t=2. Unlock timings must be taken on an idle machine.

Through the real binary, a fresh process doing `logindesk unlock` (release build) took **0.83–0.85 s** over 5 runs. That includes the page faults for 512 MiB.

The chosen default unlocks in 0.75 s (library) to 0.85 s (CLI process) on this Mac, inside the plan's 0.5–1.0 s target. A wrong password costs the same work (see below).

## Vault file

One SQLite database. `application_id = 0x4C445631` ("LDV1"), `user_version = 1`, `secure_delete = ON`. The file is created with mode `0600` and never overwritten. A missing parent directory is created with mode `0700`.

```sql
meta(key TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT      -- 'header', 'manifest'
records(id BLOB PRIMARY KEY, kind INTEGER, version INTEGER, envelope BLOB) STRICT
```

**Plaintext on disk:**
- the header (KDF parameters and salt);
- each record's random 16-byte id, its kind code (1 = login, 2 = api-key, 3 = mail credential, 4 = note) and its version number;
- the number of records;
- padded sizes.

Sites, usernames, notes, timestamps and secrets are all encrypted.

All integers are little-endian unless stated otherwise. Every decoder is strict:
- no trailing bytes;
- every length is bounded;
- canonical, so re-encoding reproduces the input exactly.

### Header (`meta.header`)

```text
magic "LDVAULT\0" | version u16 = 1 | m_kib u32 | t u32 | p u32 | salt[32]
| check_nonce[24] | len u32 | check_ct
check_ct = XChaCha20-Poly1305(K_check, check_nonce, "logindesk key check v1",
                              AD = magic..salt  (the 50-byte prefix above))
```

The key-check value authenticates the KDF parameters and the salt. A modified header makes unlock fail as `WrongPassword`, after one full Argon2id run within the bounds above.

### Record (`records.envelope`)

```text
version u16 = 1 | dek_nonce[24] | wrapped_dek[48] | body_nonce[24] | len u32 | body_ct
AD_i        = record_id[16] | kind u8 | version u64 (big-endian)          -- 25 bytes
wrapped_dek = XChaCha20-Poly1305(KEK,   dek_nonce,  DEK_i,   AD = "logindesk/v1/dek|" | AD_i)
body_ct     = XChaCha20-Poly1305(DEK_i, body_nonce, payload, AD = AD_i)
payload     = content_len u32 | content | zero padding to a multiple of 256 bytes
content     = version u16 | created_at u64 | updated_at u64
              | site | username | created_by | notes | secret      (each: len u32 | bytes, <= 64 KiB)
```

`AD_i` is taken from the authenticated manifest, never from the row's own columns.

### Manifest (`meta.manifest`)

```text
sealed   = nonce[24] | len u32 | XChaCha20-Poly1305(K_man, nonce, manifest, AD = "logindesk/v1/manifest")
manifest = version u16 | generation u64 | count u32 | (id[16] | kind u8 | version u64)* sorted by id, unique
```

Every write runs in one `BEGIN IMMEDIATE` transaction:
1. Read the manifest.
2. Write the record with version+1 under a fresh DEK and fresh nonces.
3. Write the manifest with generation+1.
4. Commit.

## Integrity: what fails closed

Each case below is a test in `crates/vault/tests/integrity.rs`.

| Attack on the file | Result |
|---|---|
| Any single bit flipped in a record envelope | `Tampered` / `Corrupt` (tested at every byte position) |
| Two records' envelopes swapped | `Tampered`: AD binds each envelope to its id |
| A record's kind changed | `Tampered`: the manifest disagrees, and so would the AD |
| An old version of a record restored (replay) | `Tampered`: the manifest's version disagrees, or the AD does |
| A row injected, or a deleted row restored | `Tampered`: not in the manifest |
| A row deleted outside logindesk | `Tampered`: the manifest lists it |
| An older manifest restored | `Tampered`: newer rows disagree with it |
| The manifest modified | `Tampered` (and unlock fails) |
| The header's KDF parameters or salt modified | `WrongPassword` |
| Not a logindesk vault, or a newer format | `Corrupt` / `Unsupported` |

**Known 0.1 limitation: whole-file rollback.**
- Restoring an older copy of the *entire* vault file (header, manifest and records together, for example from a backup or a Time Machine snapshot) is not detected, because that older copy is internally consistent.
- Detecting it needs state kept outside the file, such as a monotonic counter in the Keychain or on a second device.
- The signed device chain planned for 0.2 sync is where this gets solved. 0.1 does not try.

## Wrong password: constant work

`Vault::unlock` always runs the full Argon2id derivation and HKDF. Only then does it check the key-check value, by AEAD tag verification, which is constant-time in `chacha20poly1305`. There is no early exit and no password-length-dependent branch before the KDF.

`tests/constant_work.rs` checks this empirically. It interleaves right and wrong unlocks, uses wrong passwords of length 0, 1, 21 and 256, and requires the median wrong/right ratio to stay within 0.5–2.0. An early exit would show up as roughly 0.001.

## Process hardening

`crates/vault/src/hardening.rs` is the only module in the workspace allowed to use `unsafe`. CI enforces that.

| Measure | macOS | Linux |
|---|---|---|
| Key page locked in RAM | `mlock` | `mlock` |
| No core dumps | `setrlimit(RLIMIT_CORE, 0)` | `setrlimit(RLIMIT_CORE, 0)` |
| No debugger attach | `ptrace(PT_DENY_ATTACH)` | `prctl(PR_SET_DUMPABLE, 0)` |

The `logindesk` binary applies the last two before reading any password. If any measure fails, it reports that on stderr and carries on without it.

## Export and import

- **`vault export`** (default) writes an encrypted copy of the whole vault, under the same password, using SQLite `VACUUM INTO`. The output is created with `0600` and `O_EXCL`, and every record is verified before copying.
- **`vault export --plaintext`** writes a CSV with every secret. It needs the vault password re-entered: a second full unlock, not a y/N. It prints a warning on stderr and creates the file with `0600` and `O_EXCL`.
- **`vault import --csv`** reads Chrome, Firefox, Safari, Bitwarden and 1Password column names. Error messages give line numbers, never cell content.

**Limitation:** the `csv` crate's internal buffers are not zeroized. Plaintext from an import or a plaintext export can stay in freed memory until it is reused. The CSV file on disk is the larger exposure, and the CLI tells the user to delete it.

## Fuzzing

`fuzz/` holds its own nightly-only workspace, kept out of CI. Its target `vault_file` covers:
- the header, envelope, manifest, payload and sealed-blob decoders, each asserting that a successful decode re-encodes canonically;
- CSV import;
- opening arbitrary bytes as a vault file.

Run:

```bash
cd fuzz && cargo +nightly fuzz run vault_file -- -max_total_time=3600 -max_len=65536
```

Results for this phase (Apple M1, 2026-11-11). "Awake" is wall time minus the sleep intervals in `pmset -g log`. libFuzzer counts sleep as part of a unit's run time, which is where its "slow units" come from. Each saved slow unit replays in 5 ms.

| Run | Code | Start → end (PST) | Wall | Awake (real fuzzing) | Executions | New corpus units | Result |
|---|---|---|---|---|---|---|---|
| 1 | before the padding fix | 15:59:38 → 16:25:30 | 26 min | 26 min | 11,198,363 | 7,569 | **Crash:** `decode_payload` accepted extra padding, so a payload had several valid encodings (not memory-unsafe). Fixed in a76988e; regression test `over_padded_payload_is_rejected` |
| 2 | after the fix | 16:28:06 → 18:02:49 | 5,676 s | 17 min 53 s | 4,405,340 | 1,786 | no crash; the Mac idle-slept at 16:45 |
| 3 | after the fix | 18:03:33 → 19:16:21 | 4,366 s | 3 min 45 s | 750,021 | 499 | no crash; slept at once, lid closed (clamshell sleep) |
| 4 | after the fix | 19:17:10 → 20:19:28 | 3,735 s | 48 min 28 s | 20,896,794 | 4,868 | no crash; lid closed at 20:04 |
| **2–4** | **after the fix** | | | **70 min 6 s** | **26,052,155** | **7,153** | **no crash** |

All runs share one corpus directory, so each run starts from everything the previous ones found. At the end it holds 10,299 inputs (52 MiB on disk). Run 4's live corpus was 628 units / 851 KB at 16.7 M executions.

**Gate decision (lead, 2026-11-16):** the ~70 min of cumulative fuzzing on the fixed code, split by Mac sleep, meets the "1 h, no crash" gate.

**Future long runs:** use `caffeinate -i`. It stops idle sleep but not clamshell sleep, so keep the lid open.
