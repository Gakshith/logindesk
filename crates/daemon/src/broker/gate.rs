//! The approval gate and `wait` handles.
//!
//! `deny` refuses, `auto` mints a standing-grant token, and both run the flow
//! in the caller's thread. `ask` shows the prompt on its own thread (open up
//! to `approval_wait_max`). The caller blocks up to `approval_in_call` for an
//! answer; once answered it waits for the flow to finish and returns its
//! status. Unanswered by then, the caller gets `awaiting_approval{handle}`,
//! the flow keeps going when the user answers, and `wait{handle}` collects it.

use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

use logindesk_approver::{Action, ApprovalOutcome, ApprovalRequest, ApprovalToken};
use logindesk_core::ids::{Handle, RequestId};
use logindesk_core::status::{FailReason, Status};
use logindesk_policy::Tier;

use super::{Broker, Outcome, failed, lock};
use crate::proto::Reply;

/// What runs once a token is in hand.
pub(super) type Flow =
    Box<dyn FnOnce(&Arc<Broker>, ApprovalToken, &ApprovalRequest) -> Outcome + Send>;

enum Phase {
    /// The prompt is open.
    Asking,
    /// Answered; the flow is running.
    Running,
    /// Finished; the reply waits for its caller.
    Done(Reply),
    /// Collected.
    Taken,
}

/// One approval-gated flow in progress.
pub(super) struct Pending {
    site: String,
    phase: Mutex<Phase>,
    cv: Condvar,
    created: Instant,
}

impl Pending {
    fn set(&self, p: Phase) {
        *lock(&self.phase) = p;
        self.cv.notify_all();
    }
}

impl Broker {
    /// Mark a token's request id spent; false if it already was.
    fn spend(&self, t: &ApprovalToken) -> bool {
        lock(&self.state).spent.insert(t.request_id())
    }

    /// Apply `tier` for `action` on `site`, then run `flow` with the token.
    pub(super) fn gate(
        self: &Arc<Self>,
        client: &str,
        action: Action,
        site: &str,
        shares: Vec<String>,
        tier: Tier,
        flow: Flow,
    ) -> Outcome {
        let req = ApprovalRequest {
            request_id: RequestId::random(),
            client_name: client.to_string(),
            action,
            site: site.to_string(),
            shares,
        };
        match tier {
            Tier::Deny => Outcome::new(&failed(FailReason::GrantDenied), site),
            Tier::Auto => {
                let t = ApprovalToken::from_standing_grant(&req);
                if !self.spend(&t) {
                    return Outcome::new(&failed(FailReason::GrantDenied), site);
                }
                flow(self, t, &req)
            }
            Tier::Ask => self.ask(req, flow),
        }
    }

    fn ask(self: &Arc<Self>, req: ApprovalRequest, flow: Flow) -> Outcome {
        let p = Arc::new(Pending {
            site: req.site.clone(),
            phase: Mutex::new(Phase::Asking),
            cv: Condvar::new(),
            created: Instant::now(),
        });
        let handle = Handle::random();
        lock(&self.pending).insert(handle, Arc::clone(&p));
        let b = Arc::clone(self);
        let p2 = Arc::clone(&p);
        let spawned = std::thread::Builder::new()
            .name("logindesk-approval".into())
            .spawn(move || {
                let outcome = b.deps.approver.approve(&req, b.cfg.approval_wait_max);
                p2.set(Phase::Running);
                let out = match outcome {
                    ApprovalOutcome::Approved => match ApprovalToken::from_outcome(&req, outcome) {
                        Some(t) if b.spend(&t) => flow(&b, t, &req),
                        _ => Outcome::new(&failed(FailReason::Internal), req.site.clone()),
                    },
                    ApprovalOutcome::Denied | ApprovalOutcome::Unavailable => {
                        Outcome::new(&Status::Denied, req.site.clone())
                    }
                    ApprovalOutcome::TimedOut => {
                        Outcome::new(&failed(FailReason::Timeout), req.site.clone())
                    }
                };
                p2.set(Phase::Done(out.reply));
            });
        if spawned.is_err() {
            lock(&self.pending).remove(&handle);
            return Outcome::new(&failed(FailReason::Internal), p.site.clone());
        }
        self.collect(handle, &p)
    }

    /// Block up to `approval_in_call` for the answer; then, if answered, until
    /// the flow is done.
    fn collect(&self, handle: Handle, p: &Pending) -> Outcome {
        let deadline = Instant::now() + self.cfg.approval_in_call;
        let mut g = lock(&p.phase);
        while matches!(*g, Phase::Asking) {
            let now = Instant::now();
            if now >= deadline {
                return Outcome::new(&Status::AwaitingApproval { handle }, p.site.clone());
            }
            g = match p.cv.wait_timeout(g, deadline - now) {
                Ok((g, _)) => g,
                Err(e) => e.into_inner().0,
            };
        }
        while matches!(*g, Phase::Running) {
            g =
                p.cv.wait(g)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        let reply = match std::mem::replace(&mut *g, Phase::Taken) {
            Phase::Done(r) => r,
            // Another `wait` already took it.
            _ => Reply::failed(FailReason::SessionNotFound),
        };
        drop(g);
        lock(&self.pending).remove(&handle);
        Outcome {
            reply,
            site: p.site.clone(),
        }
    }

    /// `wait{handle}`.
    pub(super) fn wait(&self, handle: &str) -> Outcome {
        let found = handle
            .parse::<Handle>()
            .ok()
            .and_then(|h| lock(&self.pending).get(&h).cloned().map(|p| (h, p)));
        match found {
            Some((h, p)) => self.collect(h, &p),
            None => Outcome::new(&failed(FailReason::SessionNotFound), ""),
        }
    }

    /// Drop finished, uncollected flows well after any prompt could be open.
    pub(super) fn purge_pending(&self, now: Instant) {
        let keep_for = self.cfg.approval_wait_max * 2;
        lock(&self.pending).retain(|_, p| {
            let finished = matches!(*lock(&p.phase), Phase::Done(_) | Phase::Taken);
            !(finished && now.saturating_duration_since(p.created) > keep_for)
        });
    }

    /// Open approvals and uncollected results (tests, status).
    pub fn pending_count(&self) -> usize {
        lock(&self.pending).len()
    }
}
