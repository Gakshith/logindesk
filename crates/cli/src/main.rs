//! The `logindesk` binary. Skeleton: subcommands land in later phases.
#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    // stdout is reserved for MCP JSON-RPC, so all human output goes to stderr.
    eprintln!(
        "logindesk {}: not implemented yet",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::FAILURE
}
