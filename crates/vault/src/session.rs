//! An unlock session with auto-lock after idle time.
//!
//! Idle time counts on both a monotonic clock and the wall clock, and the
//! larger wins: on macOS the monotonic clock stops while the machine sleeps,
//! so a laptop closed for an hour must still lock.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use logindesk_core::SecretString;

use crate::error::{Error, Result};
use crate::keys::Keys;
use crate::vault::Vault;

/// Idle time after which an unlocked session locks itself.
pub const AUTO_LOCK_AFTER: Duration = Duration::from_secs(15 * 60);

/// A point in time on both clocks.
#[derive(Debug, Clone, Copy)]
pub struct Timestamp {
    /// Monotonic.
    pub mono: Instant,
    /// Wall clock.
    pub wall: SystemTime,
}

/// A time source (injectable for tests).
pub trait Clock {
    /// Now.
    fn now(&self) -> Timestamp;
}

/// The real clocks.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp {
            mono: Instant::now(),
            wall: SystemTime::now(),
        }
    }
}

/// A clock that only moves when told to. Clones share the same time.
#[derive(Debug, Clone)]
pub struct ManualClock(Arc<Mutex<Timestamp>>);

impl Default for ManualClock {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(SystemClock.now())))
    }
}

impl ManualClock {
    /// Starts at the real current time.
    pub fn new() -> Self {
        Self::default()
    }
    fn update(&self, f: impl FnOnce(&mut Timestamp)) {
        let mut t = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut t);
    }
    /// Advances both clocks.
    pub fn advance(&self, d: Duration) {
        self.update(|t| {
            t.mono += d;
            t.wall += d;
        });
    }
    /// Advances only the wall clock (what a sleeping Mac looks like).
    pub fn advance_wall_only(&self, d: Duration) {
        self.update(|t| t.wall += d);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Timestamp {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// A vault plus, while unlocked, its keys. Locks after [`AUTO_LOCK_AFTER`]
/// without use.
pub struct VaultSession<C: Clock = SystemClock> {
    vault: Vault,
    keys: Option<Keys>,
    clock: C,
    idle_timeout: Duration,
    last_used: Option<Timestamp>,
}

impl<C: Clock> core::fmt::Debug for VaultSession<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VaultSession")
            .field("path", &self.vault.path())
            .field("unlocked", &self.keys.is_some())
            .field("idle_timeout", &self.idle_timeout)
            .finish_non_exhaustive()
    }
}

impl<C: Clock> VaultSession<C> {
    /// A locked session.
    pub fn new(vault: Vault, clock: C) -> Self {
        Self {
            vault,
            keys: None,
            clock,
            idle_timeout: AUTO_LOCK_AFTER,
            last_used: None,
        }
    }

    /// The vault (usable while locked for non-secret things like its path).
    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Unlocks with the vault password.
    pub fn unlock(&mut self, password: &SecretString) -> Result<()> {
        let keys = self.vault.unlock(password)?;
        self.keys = Some(keys);
        self.last_used = Some(self.clock.now());
        Ok(())
    }

    /// Locks now: drops (and so zeroizes and munlocks) the keys.
    pub fn lock(&mut self) {
        self.keys = None;
        self.last_used = None;
    }

    /// Locks if idle for too long. Returns `true` if this call locked it.
    pub fn tick(&mut self) -> bool {
        let Some(last) = self.last_used else {
            return false;
        };
        if self.keys.is_none() {
            return false;
        }
        let now = self.clock.now();
        let mono = now.mono.saturating_duration_since(last.mono);
        let wall = now.wall.duration_since(last.wall).unwrap_or(Duration::ZERO);
        if mono.max(wall) >= self.idle_timeout {
            self.lock();
            true
        } else {
            false
        }
    }

    /// Whether the session is unlocked (applies the idle timeout first).
    pub fn is_unlocked(&mut self) -> bool {
        self.tick();
        self.keys.is_some()
    }

    /// Runs `f` with the unlocked vault and resets the idle timer.
    /// Returns [`Error::Locked`] if locked or idle for too long.
    pub fn with_vault<R>(&mut self, f: impl FnOnce(&mut Vault, &Keys) -> Result<R>) -> Result<R> {
        self.tick();
        let keys = self.keys.as_ref().ok_or(Error::Locked)?;
        let out = f(&mut self.vault, keys);
        self.last_used = Some(self.clock.now());
        out
    }
}
