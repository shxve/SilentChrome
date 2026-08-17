use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const FILETIME_EPOCH_OFFSET: u64 = 11_644_473_600_000_000;

pub struct Manifest {
    pub raw: Value,
    pub name: String,
    pub version: String,
    pub permissions: Vec<String>,
    pub host_permissions: Vec<String>,
    pub key: Option<String>,
    pub service_worker: Option<String>,
}

pub enum ExtId {
    FromKey(String),
    FromPath(String),
}

impl ExtId {
    pub fn id(&self) -> &str {
        match self {
            Self::FromKey(id) | Self::FromPath(id) => id,
        }
    }
}

/// Derive extension ID from a manifest key (base64-encoded public key).
/// Produces a stable ID regardless of extension path.
pub fn derive_id_from_key(base64_key: &str) -> io::Result<String> {
    use base64::Engine;
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(base64_key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad manifest key: {e}")))?;
    let digest = Sha256::digest(&key_bytes);
    Ok(nibbles_to_id(&digest))
}

/// Derive extension ID from the extension's absolute path.
/// Uses UTF-16-LE encoding on Windows, UTF-8 elsewhere.
pub fn derive_id_from_path(path: &str) -> String {
    let bytes: Vec<u8> = if cfg!(target_os = "windows") {
        path.encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect()
    } else {
        path.as_bytes().to_vec()
    };
    let digest = Sha256::digest(&bytes);
    nibbles_to_id(&digest)
}

/// Map the first 32 hex nibbles of a SHA-256 digest to Chrome's `[a-p]` alphabet.
fn nibbles_to_id(digest: &[u8]) -> String {
    digest
        .iter()
        .take(16)
        .flat_map(|byte| [byte >> 4, byte & 0x0F])
        .map(|nibble| char::from(b'a' + nibble))
        .collect()
}

/// Parse `manifest.json` from an extension directory.
pub fn parse_manifest(dir: &Path) -> io::Result<Manifest> {
    let manifest_path = dir.join("manifest.json");
    let content = std::fs::read_to_string(&manifest_path)?;
    let raw: Value = serde_json::from_str(&content).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid manifest.json: {e}"),
        )
    })?;

    let name = raw
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();

    let version = raw
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("1.0")
        .to_string();

    let permissions = extract_string_array(&raw, "permissions");
    let host_permissions = extract_string_array(&raw, "host_permissions");

    let key = raw.get("key").and_then(Value::as_str).map(String::from);

    let service_worker = raw
        .get("background")
        .and_then(|bg| bg.get("service_worker"))
        .and_then(Value::as_str)
        .map(String::from);

    Ok(Manifest {
        raw,
        name,
        version,
        permissions,
        host_permissions,
        key,
        service_worker,
    })
}

/// Resolve the extension ID: prefer manifest key (stable), fall back to path-based.
pub fn resolve_id(manifest: &Manifest, ext_path: &str) -> ExtId {
    match &manifest.key {
        Some(key) => match derive_id_from_key(key) {
            Ok(id) => ExtId::FromKey(id),
            Err(_) => ExtId::FromPath(derive_id_from_path(ext_path)),
        },
        None => ExtId::FromPath(derive_id_from_path(ext_path)),
    }
}

/// Build the `extensions.settings.<id>` JSON blob for a sideloaded extension.
pub fn build_settings(manifest: &Manifest, ext_path: &str) -> Value {
    let now = filetime_now();

    let all_permissions: Vec<Value> = manifest
        .permissions
        .iter()
        .map(|s| Value::String(s.clone()))
        .collect();

    let all_hosts: Vec<Value> = manifest
        .host_permissions
        .iter()
        .map(|s| Value::String(s.clone()))
        .collect();

    let mut settings = json!({
        "account_extension_type": 0,
        "active_permissions": {
            "api": all_permissions,
            "explicit_host": all_hosts,
            "manifest_permissions": [],
            "scriptable_host": []
        },
        "commands": {},
        "content_settings": [],
        "creation_flags": 38,
        "first_install_time": now,
        "from_bookmark": false,
        "from_webstore": false,
        "granted_permissions": {
            "api": all_permissions,
            "explicit_host": all_hosts,
            "manifest_permissions": [],
            "scriptable_host": []
        },
        "incognito": true,
        "incognito_content_settings": [],
        "incognito_preferences": {},
        "last_update_time": now,
        "location": 4,
        "manifest": manifest.raw,
        "newAllowFileAccess": true,
        "path": ext_path,
        "preferences": {},
        "regular_only_preferences": {},
        "state": 1,
        "was_installed_by_default": false,
        "was_installed_by_oem": false,
        "withholding_permissions": false
    });

    if let Some(sw) = &manifest.service_worker {
        settings["service_worker_registration_info"] =
            json!({ "version": manifest.version });
        let _ = sw; // version from manifest, not sw path
    }

    settings
}

fn filetime_now() -> String {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock");
    #[allow(clippy::cast_possible_truncation)]
    let micros = since_epoch.as_micros() as u64;
    let filetime = micros + FILETIME_EPOCH_OFFSET;
    filetime.to_string()
}

fn extract_string_array(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_id_from_path_linux() {
        let id = derive_id_from_path("/tmp/test_extension");
        assert_eq!(id, "abkadfbcnpenojlncdmkijflkbadnmeb");
    }

    #[test]
    fn test_nibbles_to_id() {
        let digest = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                      0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let id = nibbles_to_id(&digest);
        assert_eq!(id, "abcdefghijklmnopabcdefghijklmnop");
    }
}
