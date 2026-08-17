use std::io;

/// Returns the device identifier used by Chromium's `PrefHashCalculator`.
///
/// - Windows: machine SID (user SID with the RID segment trimmed)
/// - macOS: Hardware UUID from `system_profiler`
/// - Linux: empty string (seed is also empty — vestigial protection)
#[allow(clippy::unnecessary_wraps)]
pub fn get_device_id() -> io::Result<String> {
    #[cfg(target_os = "windows")]
    {
        windows_device_id()
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

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn windows_device_id() -> io::Result<String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::LookupAccountNameW;

    let username = std::env::var("USERNAME").map_err(|e| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("USERNAME environment variable: {e}"),
        )
    })?;

    let username_wide: Vec<u16> = username.encode_utf16().chain(std::iter::once(0)).collect();

    let mut sid_buf = [0u8; 256];
    #[allow(clippy::cast_possible_truncation)]
    let mut sid_len = sid_buf.len() as u32;
    let mut domain_buf = [0u16; 256];
    #[allow(clippy::cast_possible_truncation)]
    let mut domain_len = domain_buf.len() as u32;
    let mut sid_type: i32 = 0;

    let ok = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            username_wide.as_ptr(),
            sid_buf.as_mut_ptr().cast(),
            &raw mut sid_len,
            domain_buf.as_mut_ptr(),
            &raw mut domain_len,
            &raw mut sid_type,
        )
    };

    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut sid_str_ptr: *mut u16 = std::ptr::null_mut();
    let ok =
        unsafe { ConvertSidToStringSidW(sid_buf.as_mut_ptr().cast(), &raw mut sid_str_ptr) };

    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    let sid_string = unsafe {
        let mut len = 0;
        let mut p = sid_str_ptr;
        while *p != 0 {
            len += 1;
            p = p.add(1);
        }
        let slice = std::slice::from_raw_parts(sid_str_ptr, len);
        let s = String::from_utf16_lossy(slice);
        LocalFree(sid_str_ptr.cast());
        s
    };

    // Trim the last RID segment: S-1-5-21-xxx-xxx-xxx-1001 → S-1-5-21-xxx-xxx-xxx
    match sid_string.rsplit_once('-') {
        Some((machine_sid, _rid)) => Ok(machine_sid.to_string()),
        None => Ok(sid_string),
    }
}
