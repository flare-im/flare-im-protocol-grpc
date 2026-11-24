//! Wire documents shared by publishers, deployment tools and client providers.
//!
//! Contains DSSE, certificate verification and the DNS pointer codec.

pub mod doh;
pub mod manifest;
pub mod network;
pub mod parsed_url;
pub mod time;
pub mod trust;
pub mod types;
pub mod update;

pub use manifest::{AccessManifest, ClientPolicy, ReleaseManifest};
pub use parsed_url::{ParsedUrl, UrlError};
pub use trust::{TrustError, TrustStore};
pub use types::{ApId, ApStatus, Protocol, ServiceClass, ServiceKind};
