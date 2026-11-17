//! Where the daemon's socket lives. Shared by the daemon (bind) and its clients (connect).

use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Socket file name.
pub const SOCKET: &str = "daemon.sock";

/// macOS `sun_path` is 104 bytes, Linux 108; stay under both.
const MAX_SOCKET_PATH: usize = 100;

/// `<data dir>/daemon.sock`, or, when that is too long for a Unix socket,
/// `/tmp/logindesk-<hash of data dir>/daemon.sock` in a 0700 directory owned by
/// the same user as the data dir (refused otherwise).
pub fn socket_path(data_dir: &Path) -> io::Result<PathBuf> {
    let direct = data_dir.join(SOCKET);
    if direct.as_os_str().len() < MAX_SOCKET_PATH {
        return Ok(direct);
    }
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    data_dir.hash(&mut h);
    let dir = PathBuf::from(format!("/tmp/logindesk-{:016x}", h.finish()));
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let owner = std::fs::metadata(data_dir).map(|m| m.uid());
    let m = std::fs::symlink_metadata(&dir)?;
    let ok =
        m.is_dir() && m.permissions().mode() & 0o077 == 0 && owner.map_or(true, |u| u == m.uid());
    if !ok {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socket fallback directory is not a private directory owned by you",
        ));
    }
    Ok(dir.join(SOCKET))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_and_long() {
        assert_eq!(
            socket_path(Path::new("/x")).unwrap(),
            PathBuf::from("/x/daemon.sock")
        );
        let d = std::env::temp_dir().join("a".repeat(120));
        std::fs::create_dir_all(&d).unwrap();
        let p = socket_path(&d).unwrap();
        assert!(p.as_os_str().len() < MAX_SOCKET_PATH, "{p:?}");
        assert_eq!(p, socket_path(&d).unwrap());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
