//! logindesk-policy: site rules and per-site grants.
#![forbid(unsafe_code)]

pub mod grants;
pub mod site;

pub use grants::{Grants, Tier};
pub use site::{registrable_domain, site_of, url_site};
