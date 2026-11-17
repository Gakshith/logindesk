//! macOS LocalAuthentication sheet (Touch ID or Mac password). The only module in this
//! crate allowed `unsafe`: every block is an objc2 FFI call into LocalAuthentication.

use std::sync::mpsc;
use std::time::Duration;

use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};

use crate::{ApprovalOutcome, ApprovalRequest, Approver};

/// Shows the system authentication sheet for each request.
#[derive(Debug, Default)]
pub struct MacApprover;

impl Approver for MacApprover {
    fn approve(&self, req: &ApprovalRequest, limit: Duration) -> ApprovalOutcome {
        // A fresh context per request: no reuse window, no cached success.
        // SAFETY: plain constructor, no preconditions.
        let ctx = unsafe { LAContext::new() };
        // SAFETY: valid context; the error out-param is handled by objc2.
        if unsafe { ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication) }.is_err() {
            return ApprovalOutcome::Unavailable;
        }
        let (tx, rx) = mpsc::channel::<bool>();
        let block = RcBlock::new(move |ok: Bool, err: *mut NSError| {
            // Approved only on success with no error object (spike 1 rule).
            let approved = ok.as_bool() && err.is_null();
            let _ = tx.send(approved);
        });
        // SAFETY: valid context, valid NSString, the block lives until the reply fires
        // (LocalAuthentication copies it).
        unsafe {
            ctx.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthentication,
                &NSString::from_str(&req.prompt_text()),
                &block,
            );
        }
        match rx.recv_timeout(limit) {
            Ok(true) => ApprovalOutcome::Approved,
            Ok(false) => ApprovalOutcome::Denied,
            Err(_) => {
                // SAFETY: valid context; invalidate dismisses the sheet.
                unsafe { ctx.invalidate() };
                ApprovalOutcome::TimedOut
            }
        }
    }
}
