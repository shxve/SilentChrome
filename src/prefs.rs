//! Filesystem orchestration around `secpref-kit`'s Secure Preferences model.

use std::fs;
use std::io::{self, Write as _};
use std::path::Path;

use serde_json::Value;

pub use secpref_kit::prefs::{ExtInfo, VerifyResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallResult {
    pub extension_id: String,
    pub mac: String,
    pub super_mac: String,
}

/// Install an unpacked extension and atomically replace the preferences file.
pub fn install(
    prefs_path: &Path,
    ext_dir: &Path,
    seed: &[u8],
    device_id: &str,
) -> io::Result<InstallResult> {
    let (canonical_ext, ext_path) =
        secpref_kit::canonical_extension_path(ext_dir).map_err(kit_error)?;
    let manifest = secpref_kit::manifest::parse(&canonical_ext).map_err(kit_error)?;
    let extension_id = secpref_kit::resolve_ext_id(manifest.key.as_deref(), &ext_path).into_id();
    let settings = secpref_kit::manifest::build_default_settings(&manifest, &ext_path);

    let mut data = read_json(prefs_path)?;
    let mac =
        secpref_kit::prefs::add_extension(&mut data, &extension_id, settings, seed, device_id)
            .map_err(kit_error)?;
    secpref_kit::prefs::enable_developer_mode(&mut data, seed, device_id);
    secpref_kit::prefs::strip_encrypted_hashes(&mut data);
    let super_mac = secpref_kit::prefs::recompute_super_mac(&mut data, seed, device_id);
    write_json_atomic(prefs_path, &data)?;

    Ok(InstallResult {
        extension_id,
        mac,
        super_mac,
    })
}

/// Remove an extension and atomically replace the preferences file.
pub fn uninstall(prefs_path: &Path, ext_id: &str, seed: &[u8], device_id: &str) -> io::Result<()> {
    let mut data = read_json(prefs_path)?;
    secpref_kit::prefs::remove_extension(&mut data, ext_id).map_err(kit_error)?;
    secpref_kit::prefs::strip_encrypted_hashes(&mut data);
    secpref_kit::prefs::recompute_super_mac(&mut data, seed, device_id);
    write_json_atomic(prefs_path, &data)
}

/// List all extensions in the preferences file.
pub fn list(prefs_path: &Path) -> io::Result<Vec<ExtInfo>> {
    Ok(secpref_kit::prefs::list_extensions(&read_json(prefs_path)?))
}

/// Verify all integrity values maintained for an extension.
pub fn verify(
    prefs_path: &Path,
    ext_id: &str,
    seed: &[u8],
    device_id: &str,
) -> io::Result<VerifyResult> {
    secpref_kit::prefs::verify_extension(&read_json(prefs_path)?, ext_id, seed, device_id)
        .map_err(kit_error)
}

fn read_json(path: &Path) -> io::Result<Value> {
    let content = fs::read_to_string(path)?;
    serde_json::from_str(&content).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid preferences JSON: {error}"),
        )
    })
}

fn write_json_atomic(path: &Path, value: &Value) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    if let Ok(metadata) = fs::metadata(path) {
        temporary
            .as_file()
            .set_permissions(metadata.permissions())?;
    }
    serde_json::to_writer(&mut temporary, value).map_err(io::Error::other)?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map(|_| ())
        .map_err(|error| error.error)
}

fn kit_error(error: secpref_kit::SecPrefError) -> io::Error {
    match error {
        secpref_kit::SecPrefError::Io(error) => error,
        secpref_kit::SecPrefError::ExtensionNotFound(_) => {
            io::Error::new(io::ErrorKind::NotFound, error.to_string())
        }
        _ => io::Error::new(io::ErrorKind::InvalidData, error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn consumer_install_verify_list_uninstall_round_trip() {
        let profile = tempfile::tempdir().unwrap();
        let extension = tempfile::tempdir().unwrap();
        let prefs_path = profile.path().join("Secure Preferences");
        fs::write(&prefs_path, "{}").unwrap();
        fs::write(
            extension.path().join("manifest.json"),
            json!({
                "manifest_version": 3,
                "name": "Convergence Fixture",
                "version": "1.0.0",
                "background": {"service_worker": "worker.js"}
            })
            .to_string(),
        )
        .unwrap();

        let seed = [0x42; secpref_kit::SEED_LEN];
        let device_id = "S-1-5-21-111-222-333";
        let installed = install(&prefs_path, extension.path(), &seed, device_id).unwrap();

        let verdict = verify(&prefs_path, &installed.extension_id, &seed, device_id).unwrap();
        assert!(
            verdict.all_valid(),
            "consumer output must satisfy kit: {verdict:?}"
        );
        let listed = list(&prefs_path).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "Convergence Fixture");
        let (_, expected_path) = secpref_kit::canonical_extension_path(extension.path()).unwrap();
        assert_eq!(listed[0].path, expected_path);

        uninstall(&prefs_path, &installed.extension_id, &seed, device_id).unwrap();
        assert!(list(&prefs_path).unwrap().is_empty());
    }

    #[test]
    fn malformed_preferences_are_not_replaced() {
        let profile = tempfile::tempdir().unwrap();
        let extension = tempfile::tempdir().unwrap();
        let prefs_path = profile.path().join("Secure Preferences");
        fs::write(&prefs_path, "not-json").unwrap();
        fs::write(
            extension.path().join("manifest.json"),
            r#"{"manifest_version":3,"name":"Fixture","version":"1"}"#,
        )
        .unwrap();

        let result = install(&prefs_path, extension.path(), &[], "");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(fs::read_to_string(&prefs_path).unwrap(), "not-json");
    }
}
