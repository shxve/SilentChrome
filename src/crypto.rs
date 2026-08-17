use std::io;
use std::path::Path;

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const DATAPACK_VERSION: u32 = 5;
const SEED_LEN: usize = 64;

/// Extract the 64-byte `chrome_seed` from a `resources.pak` file (`DataPack` v5).
///
/// Walks resource entries in ascending ID order and returns the first resource
/// whose length is exactly 64 bytes.
pub fn extract_seed(pak_path: &Path) -> io::Result<Vec<u8>> {
    let data = std::fs::read(pak_path)?;
    if data.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "resources.pak too small for DataPack v5 header",
        ));
    }

    let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if version != DATAPACK_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected DataPack version {DATAPACK_VERSION}, got {version}"),
        ));
    }

    let resource_count = u16::from_le_bytes(data[8..10].try_into().unwrap()) as usize;
    let _alias_count = u16::from_le_bytes(data[10..12].try_into().unwrap());

    let entries_start = 12;
    let entry_size = 6; // u16 resource_id + u32 offset
    let total_entries = resource_count + 1; // +1 sentinel

    if data.len() < entries_start + total_entries * entry_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "resources.pak truncated: not enough entry data",
        ));
    }

    for i in 0..resource_count {
        let base = entries_start + i * entry_size;
        let offset = u32::from_le_bytes(data[base + 2..base + 6].try_into().unwrap()) as usize;
        let next_base = entries_start + (i + 1) * entry_size;
        let next_offset =
            u32::from_le_bytes(data[next_base + 2..next_base + 6].try_into().unwrap()) as usize;

        let len = next_offset.saturating_sub(offset);
        if len == SEED_LEN {
            if next_offset > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "resource offset exceeds file size",
                ));
            }
            return Ok(data[offset..next_offset].to_vec());
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no 64-byte resource found in resources.pak",
    ))
}

/// Compute a per-preference MAC.
///
/// `HMAC-SHA256(seed, device_id || pref_path || canonicalize(value))` → uppercase hex.
pub fn compute_mac(seed: &[u8], device_id: &str, pref_path: &str, value: &Value) -> String {
    let canonical = canonicalize(value);
    let message = format!("{device_id}{pref_path}{canonical}");
    hmac_hex(seed, message.as_bytes())
}

/// Compute the `super_mac` over the entire `protection.macs` subtree.
///
/// `HMAC-SHA256(seed, device_id || compact_json(macs))` → uppercase hex.
pub fn compute_super_mac(seed: &[u8], device_id: &str, macs: &Value) -> String {
    let macs_json = serde_json::to_string(macs).expect("macs serialization");
    let message = format!("{device_id}{macs_json}");
    hmac_hex(seed, message.as_bytes())
}

fn hmac_hex(seed: &[u8], message: &[u8]) -> String {
    use std::fmt::Write;
    let mut mac = HmacSha256::new_from_slice(seed).expect("HMAC accepts any key length");
    mac.update(message);
    let result = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(result.len() * 2);
    for byte in &result {
        let _ = write!(hex, "{byte:02X}");
    }
    hex
}

/// Serialize a JSON value for HMAC input following Chromium's `JSONWriter` conventions:
/// 1. Compact (no whitespace)
/// 2. Insertion-order keys (`serde_json` `preserve_order`)
/// 3. Strip empty objects/arrays/strings and nulls (preserve `false` and `0`)
/// 4. Replace `<` with `<`
fn canonicalize(value: &Value) -> String {
    let mut v = value.clone();
    strip_empties(&mut v);
    let json = serde_json::to_string(&v).expect("JSON serialization");
    json.replace('<', "\\u003C")
}

/// Recursively remove keys whose values are empty objects, empty arrays,
/// empty strings, or null. Preserve `false` and `0`.
pub fn strip_empties(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let keys_to_remove: Vec<String> = map
                .iter()
                .filter_map(|(k, v)| if is_empty(v) { Some(k.clone()) } else { None })
                .collect();
            for k in &keys_to_remove {
                map.swap_remove(k);
            }
            for v in map.values_mut() {
                strip_empties(v);
            }
            let keys_to_remove: Vec<String> = map
                .iter()
                .filter_map(|(k, v)| if is_empty(v) { Some(k.clone()) } else { None })
                .collect();
            for k in &keys_to_remove {
                map.swap_remove(k);
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                strip_empties(item);
            }
            arr.retain(|v| !is_empty(v));
        }
        _ => {}
    }
}

fn is_empty(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.is_empty(),
        Value::Array(arr) => arr.is_empty(),
        Value::String(s) => s.is_empty(),
        Value::Null => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_compute_mac_empty_seed() {
        let mac = compute_mac(b"", "", "extensions.ui.developer_mode", &Value::Bool(true));
        assert_eq!(
            mac,
            "F1323889EA777F2EB3E23F3E2CFCB59D3FAFCB8DE80104742CBF2A9E44046ED9"
        );
    }

    #[test]
    fn test_compute_mac_known_seed() {
        let seed = [b'A'; 64];
        let value = json!({"key1": "value1", "key2": 42});
        let mac = compute_mac(&seed, "S-1-5-21-123", "extensions.settings.testid", &value);
        assert_eq!(
            mac,
            "B33251DEB592061EDBCE92A14F009D37181A0F9F5B64605CC01764E1CAE12471"
        );
    }

    #[test]
    fn test_strip_empties() {
        let mut v = json!({
            "keep": 42,
            "keep_false": false,
            "keep_zero": 0,
            "drop_empty_obj": {},
            "drop_empty_arr": [],
            "drop_empty_str": "",
            "drop_null": null,
            "nested": {
                "inner_keep": "yes",
                "inner_drop": {}
            }
        });
        strip_empties(&mut v);
        assert!(v.get("keep").is_some());
        assert!(v.get("keep_false").is_some());
        assert!(v.get("keep_zero").is_some());
        assert!(v.get("drop_empty_obj").is_none());
        assert!(v.get("drop_empty_arr").is_none());
        assert!(v.get("drop_empty_str").is_none());
        assert!(v.get("drop_null").is_none());
        let nested = v.get("nested").unwrap();
        assert!(nested.get("inner_keep").is_some());
        assert!(nested.get("inner_drop").is_none());
    }

    #[test]
    fn test_canonicalize_angle_bracket() {
        let v = json!({"host": "<all_urls>"});
        let c = canonicalize(&v);
        assert!(c.contains("\\u003C"));
        assert!(!c.contains('<'));
    }
}
