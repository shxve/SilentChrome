#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

mod browser;
mod identity;
mod prefs;

pub use browser::Browser;
pub use prefs::{ExtInfo, InstallResult, VerifyResult, install, list, uninstall, verify};
pub use secpref_kit::ExtId;
pub use secpref_kit::manifest::Manifest;

pub fn identity_device_id() -> std::io::Result<String> {
    identity::get_device_id()
}
