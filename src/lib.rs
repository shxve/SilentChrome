#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

mod browser;
mod crypto;
mod ext;
mod identity;
mod prefs;

pub use browser::Browser;
pub use crypto::extract_seed;
pub use ext::{ExtId, Manifest};
pub use prefs::{install, list, uninstall, verify, ExtInfo, InstallResult, VerifyResult};

pub fn identity_device_id() -> std::io::Result<String> {
    identity::get_device_id()
}
