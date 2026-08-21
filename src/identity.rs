use std::io;

/// Returns the device identifier used by Chromium's `PrefHashCalculator`.
///
/// - Windows: machine SID, resolved the same way Chromium resolves it
/// - macOS: Hardware UUID from `system_profiler`
/// - Linux: empty string (seed is also empty — vestigial protection)
#[allow(clippy::unnecessary_wraps)]
pub fn get_device_id() -> io::Result<String> {
    #[cfg(target_os = "windows")]
    {
        secpref_kit::sid::machine_id().map_err(|error| io::Error::other(error.to_string()))
    }
    #[cfg(target_os = "macos")]
    {
        macos_device_id()
    }
    #[cfg(target_os = "linux")]
    {
        Ok(String::new())
    }
}

#[cfg(target_os = "macos")]
fn macos_device_id() -> io::Result<String> {
    let output = std::process::Command::new("system_profiler")
        .arg("SPHardwareDataType")
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Hardware UUID:") || trimmed.starts_with("UUID:") {
            if let Some(uuid) = trimmed.split(':').nth(1) {
                return Ok(uuid.trim().to_string());
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Hardware UUID not found in system_profiler output",
    ))
}
