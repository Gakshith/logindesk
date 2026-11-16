//! Process and memory hardening. **The only module in the workspace that may
//! use `unsafe`**; `lib.rs` allows `unsafe_code` for this module alone and the
//! crate otherwise denies it. Every `unsafe` block states why it is sound.
//!
//! - [`LockedPage`]: a page-aligned, page-sized heap allocation that is
//!   `mlock`ed (kept out of swap), owned exclusively (so `munlock` on drop
//!   cannot unlock someone else's data), and zeroized before it is freed.
//! - [`disable_core_dumps`]: `setrlimit(RLIMIT_CORE, 0)`.
//! - [`deny_debugger_attach`]: `ptrace(PT_DENY_ATTACH)` on macOS,
//!   `prctl(PR_SET_DUMPABLE, 0)` on Linux.

use std::alloc::{Layout, alloc_zeroed, dealloc, handle_alloc_error};
use std::fmt;
use std::io;
use std::ptr::NonNull;

use zeroize::Zeroize;

/// Usable bytes in a [`LockedPage`] (the rest of the page stays zero).
pub const LOCKED_LEN: usize = 256;

/// Exclusively owned, page-aligned, mlocked, zeroize-on-drop key memory.
pub struct LockedPage {
    ptr: NonNull<u8>,
    layout: Layout,
    mlocked: bool,
}

// SAFETY: `LockedPage` uniquely owns its allocation (no aliasing pointers are
// ever handed out except through `&self`/`&mut self` borrows), so moving it to
// another thread or sharing `&LockedPage` across threads is as safe as for a
// `Box<[u8]>`.
unsafe impl Send for LockedPage {}
// SAFETY: see above; `&LockedPage` only gives out `&[u8]`.
unsafe impl Sync for LockedPage {}

fn page_size() -> usize {
    // SAFETY: `sysconf` takes no pointers and is thread-safe.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n > 0 { n as usize } else { 4096 }
}

impl LockedPage {
    /// Allocates one zeroed page and tries to `mlock` it. A failed `mlock`
    /// (for example a low `RLIMIT_MEMLOCK`) is not fatal: check
    /// [`Self::is_mlocked`].
    pub fn new() -> Self {
        let size = page_size().max(LOCKED_LEN);
        let layout = match Layout::from_size_align(size, size) {
            Ok(l) => l,
            Err(_) => handle_alloc_error(Layout::new::<[u8; LOCKED_LEN]>()),
        };
        // SAFETY: `layout` has a non-zero size.
        let raw = unsafe { alloc_zeroed(layout) };
        let Some(ptr) = NonNull::new(raw) else {
            handle_alloc_error(layout)
        };
        // SAFETY: `ptr` points to `layout.size()` bytes that this function just
        // allocated and owns; `mlock` only reads the address range.
        let mlocked = unsafe { libc::mlock(ptr.as_ptr().cast(), layout.size()) } == 0;
        Self {
            ptr,
            layout,
            mlocked,
        }
    }

    /// Whether the page is locked in RAM.
    pub fn is_mlocked(&self) -> bool {
        self.mlocked
    }

    /// The usable bytes.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: the allocation is at least LOCKED_LEN bytes, initialised
        // (zeroed at allocation), uniquely owned, and lives as long as `self`.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), LOCKED_LEN) }
    }

    /// The usable bytes, mutably.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as in `as_slice`, and `&mut self` guarantees exclusivity.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), LOCKED_LEN) }
    }
}

impl Default for LockedPage {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for LockedPage {
    fn drop(&mut self) {
        // SAFETY: the whole allocation is valid, initialised and exclusively
        // ours for the duration of `drop`.
        let all = unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.layout.size()) };
        all.zeroize();
        if self.mlocked {
            // SAFETY: same range we locked in `new`; nobody else owns this page.
            unsafe { libc::munlock(self.ptr.as_ptr().cast(), self.layout.size()) };
        }
        // SAFETY: `ptr` came from `alloc_zeroed(self.layout)` and is freed once.
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) };
    }
}

impl fmt::Debug for LockedPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedPage")
            .field("mlocked", &self.mlocked)
            .finish_non_exhaustive()
    }
}

/// Sets the core-dump size limit (soft and hard) to zero for this process.
pub fn disable_core_dumps() -> io::Result<()> {
    let rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `&rl` is a valid pointer to an initialised `rlimit`.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rl) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// The current (soft, hard) core-dump limit.
pub fn core_dump_limit() -> io::Result<(libc::rlim_t, libc::rlim_t)> {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `&mut rl` is a valid, writable pointer to an `rlimit`.
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut rl) } == 0 {
        Ok((rl.rlim_cur, rl.rlim_max))
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Stops debuggers from attaching to this process.
///
/// macOS: `ptrace(PT_DENY_ATTACH)`; an attached debugger makes the process
/// exit. Linux: `prctl(PR_SET_DUMPABLE, 0)`, which also blocks same-user
/// ptrace and core dumps. Elsewhere: `Unsupported`.
pub fn deny_debugger_attach() -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: PT_DENY_ATTACH ignores the pid, addr and data arguments and
        // dereferences no pointer.
        let rc = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_DUMPABLE takes only integer arguments.
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_page_is_zeroed_writable_and_mlocked() {
        let mut p = LockedPage::new();
        assert!(p.as_slice().iter().all(|&b| b == 0));
        p.as_mut_slice()[..4].copy_from_slice(b"KEY!");
        assert_eq!(&p.as_slice()[..4], b"KEY!");
        // mlock of one page is within every default RLIMIT_MEMLOCK we target.
        assert!(p.is_mlocked(), "mlock failed");
        assert!(format!("{p:?}").contains("mlocked"));
    }

    #[test]
    fn core_dumps_can_be_disabled() {
        disable_core_dumps().unwrap();
        assert_eq!(core_dump_limit().unwrap(), (0, 0));
    }

    #[test]
    fn debugger_attach_can_be_denied() {
        deny_debugger_attach().unwrap();
    }
}
