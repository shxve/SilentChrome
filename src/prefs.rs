use std::io;
use std::path::Path;

use serde_json::Value;

use crate::crypto;
use crate::ext;

pub struct InstallResult {
    pub extension_id: String,
    pub mac: String,
    pub super_mac: String,
}

pub struct ExtInfo {
    pub id: String,
    pub name: String,
    pub path: String,
    pub version: String,
    pub enabled: bool,
}

pub struct VerifyResult {
    pub ext_mac_valid: bool,
    pub dev_mac_valid: bool,
    pub super_mac_valid: bool,
}

/// Install an extension into the Secure Preferences file.
///
/// 1. Parse the extension's manifest
/// 2. Derive the extension ID (prefer manifest key, fall back to path)
/// 3. Build the settings blob and strip empties
/// 4. Inject into `extensions.settings.<id>`
/// 5. Enable developer mode
/// 6. Strip all `_encrypted_hash` entries
/// 7. Compute per-preference MACs
/// 8. Compute `super_mac`
/// 9. Write the file (single write)
pub fn install(
    prefs_path: &Path,
    ext_dir: &Path,
    seed: &[u8],
    device_id: &str,
) -> io::Result<InstallResult> {
    let manifest = ext::parse_manifest(ext_dir)?;

    let ext_path_str = ext_dir.to_string_lossy().to_string();
    let ext_id_result = ext::resolve_id(&manifest, &ext_path_str);
    let ext_id = ext_id_result.id().to_string();

    let mut settings = ext::build_settings(&manifest, &ext_path_str);
    crypto::strip_empties(&mut settings);

    let content = std::fs::read_to_string(prefs_path)?;
    let mut data: Value = serde_json::from_str(&content).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid prefs JSON: {e}"))
    })?;

    // Inject extension settings
    ensure_object(&mut data, &["extensions", "settings"])[&ext_id] = settings.clone();

    // Enable developer mode
    ensure_object(&mut data, &["extensions", "ui"])
        .insert("developer_mode".to_string(), Value::Bool(true));

    // Enable developer mode for signed-in profile
    ensure_object(&mut data, &["account_values", "extensions", "ui"])
        .insert("developer_mode".to_string(), Value::Bool(true));

    // Strip all encrypted_hash entries from the entire tree
    strip_encrypted_hashes(&mut data);

    // Compute per-preference MACs
    let ext_mac_path = format!("extensions.settings.{ext_id}");
    let ext_mac = crypto::compute_mac(seed, device_id, &ext_mac_path, &settings);

    ensure_object(&mut data, &["protection", "macs", "extensions", "settings"])
        .insert(ext_id.clone(), Value::String(ext_mac.clone()));

    let dev_mac = crypto::compute_mac(
        seed,
        device_id,
        "extensions.ui.developer_mode",
        &Value::Bool(true),
    );
    ensure_object(&mut data, &["protection", "macs", "extensions", "ui"])
        .insert("developer_mode".to_string(), Value::String(dev_mac));

    let account_dev_mac = crypto::compute_mac(
        seed,
        device_id,
        "account_values.extensions.ui.developer_mode",
        &Value::Bool(true),
    );
    ensure_object(
        &mut data,
        &[
            "protection",
            "macs",
            "account_values",
            "extensions",
            "ui",
        ],
    )
    .insert(
        "developer_mode".to_string(),
        Value::String(account_dev_mac),
    );

    // Compute super_mac over the (now clean) macs subtree
    let macs = data
        .get("protection")
        .and_then(|p| p.get("macs"))
        .cloned()
        .unwrap_or(Value::Object(serde_json::Map::new()));

    let super_mac = crypto::compute_super_mac(seed, device_id, &macs);
    ensure_object(&mut data, &["protection"])
        .insert("super_mac".to_string(), Value::String(super_mac.clone()));

    let output = serde_json::to_string(&data).map_err(|e| {
        io::Error::other(format!("JSON serialization: {e}"))
    })?;
    std::fs::write(prefs_path, output)?;

    Ok(InstallResult {
        extension_id: ext_id,
        mac: ext_mac,
        super_mac,
    })
}

/// Remove a sideloaded extension and recompute MACs.
pub fn uninstall(
    prefs_path: &Path,
    ext_id: &str,
    seed: &[u8],
    device_id: &str,
) -> io::Result<()> {
    let content = std::fs::read_to_string(prefs_path)?;
    let mut data: Value = serde_json::from_str(&content).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid prefs JSON: {e}"))
    })?;

    // Remove extension settings
    if let Some(settings) = data
        .get_mut("extensions")
        .and_then(|e| e.get_mut("settings"))
        .and_then(Value::as_object_mut)
    {
        if settings.swap_remove(ext_id).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("extension {ext_id} not found in settings"),
            ));
        }
    } else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "extensions.settings not found",
        ));
    }

    // Remove extension MAC
    if let Some(macs) = data
        .get_mut("protection")
        .and_then(|p| p.get_mut("macs"))
        .and_then(|m| m.get_mut("extensions"))
        .and_then(|e| e.get_mut("settings"))
        .and_then(Value::as_object_mut)
    {
        macs.swap_remove(ext_id);
    }

    strip_encrypted_hashes(&mut data);

    // Recompute super_mac
    let macs = data
        .get("protection")
        .and_then(|p| p.get("macs"))
        .cloned()
        .unwrap_or(Value::Object(serde_json::Map::new()));

    let super_mac = crypto::compute_super_mac(seed, device_id, &macs);
    ensure_object(&mut data, &["protection"])
        .insert("super_mac".to_string(), Value::String(super_mac));

    let output = serde_json::to_string(&data).map_err(|e| {
        io::Error::other(format!("JSON serialization: {e}"))
    })?;
    std::fs::write(prefs_path, output)?;

    Ok(())
}

/// List all extensions in the preferences file.
pub fn list(prefs_path: &Path) -> io::Result<Vec<ExtInfo>> {
    let content = std::fs::read_to_string(prefs_path)?;
    let data: Value = serde_json::from_str(&content).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid prefs JSON: {e}"))
    })?;

    let Some(Value::Object(settings)) =
        data.get("extensions").and_then(|e| e.get("settings"))
    else {
        return Ok(Vec::new());
    };

    let mut extensions = Vec::new();
    for (id, ext) in settings {
        let name = ext
            .get("manifest")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("(unknown)")
            .to_string();

        let path = ext
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let version = ext
            .get("manifest")
            .and_then(|m| m.get("version"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let state = ext.get("state").and_then(Value::as_i64).unwrap_or(0);

        extensions.push(ExtInfo {
            id: id.clone(),
            name,
            path,
            version,
            enabled: state == 1,
        });
    }

    Ok(extensions)
}

/// Verify that an extension's MACs are valid.
pub fn verify(
    prefs_path: &Path,
    ext_id: &str,
    seed: &[u8],
    device_id: &str,
) -> io::Result<VerifyResult> {
    let content = std::fs::read_to_string(prefs_path)?;
    let data: Value = serde_json::from_str(&content).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid prefs JSON: {e}"))
    })?;

    // Get stored extension settings and MAC
    let ext_settings = data
        .get("extensions")
        .and_then(|e| e.get("settings"))
        .and_then(|s| s.get(ext_id))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("extension {ext_id} not found"),
            )
        })?;

    let stored_ext_mac = data
        .get("protection")
        .and_then(|p| p.get("macs"))
        .and_then(|m| m.get("extensions"))
        .and_then(|e| e.get("settings"))
        .and_then(|s| s.get(ext_id))
        .and_then(Value::as_str)
        .unwrap_or("");

    let ext_mac_path = format!("extensions.settings.{ext_id}");
    let computed_ext_mac = crypto::compute_mac(seed, device_id, &ext_mac_path, ext_settings);
    let ext_mac_valid = computed_ext_mac.eq_ignore_ascii_case(stored_ext_mac);

    // Verify developer_mode MAC
    let stored_dev_mac = data
        .get("protection")
        .and_then(|p| p.get("macs"))
        .and_then(|m| m.get("extensions"))
        .and_then(|e| e.get("ui"))
        .and_then(|u| u.get("developer_mode"))
        .and_then(Value::as_str)
        .unwrap_or("");

    let computed_dev_mac = crypto::compute_mac(
        seed,
        device_id,
        "extensions.ui.developer_mode",
        &Value::Bool(true),
    );
    let dev_mac_valid = computed_dev_mac.eq_ignore_ascii_case(stored_dev_mac);

    // Verify super_mac
    let stored_super = data
        .get("protection")
        .and_then(|p| p.get("super_mac"))
        .and_then(Value::as_str)
        .unwrap_or("");

    let macs = data
        .get("protection")
        .and_then(|p| p.get("macs"))
        .cloned()
        .unwrap_or(Value::Object(serde_json::Map::new()));

    let computed_super = crypto::compute_super_mac(seed, device_id, &macs);
    let super_mac_valid = computed_super.eq_ignore_ascii_case(stored_super);

    Ok(VerifyResult {
        ext_mac_valid,
        dev_mac_valid,
        super_mac_valid,
    })
}

/// Recursively remove all keys containing `_encrypted_hash`.
fn strip_encrypted_hashes(value: &mut Value) {
    if let Value::Object(map) = value {
        let keys_to_remove: Vec<String> = map
            .keys()
            .filter(|k| k.contains("_encrypted_hash"))
            .cloned()
            .collect();
        for k in &keys_to_remove {
            map.swap_remove(k);
        }
        for v in map.values_mut() {
            strip_encrypted_hashes(v);
        }
    } else if let Value::Array(arr) = value {
        for item in arr.iter_mut() {
            strip_encrypted_hashes(item);
        }
    }
}

/// Navigate into nested objects, creating intermediate objects as needed.
/// Returns a mutable reference to the innermost object's map.
fn ensure_object<'a>(
    root: &'a mut Value,
    keys: &[&str],
) -> &'a mut serde_json::Map<String, Value> {
    let mut current = root;
    for &key in keys {
        if !current.get(key).is_some_and(Value::is_object) {
            current[key] = Value::Object(serde_json::Map::new());
        }
        current = current.get_mut(key).expect("just created");
    }
    current.as_object_mut().expect("guaranteed object")
}
