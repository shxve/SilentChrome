use std::io;
use std::path::PathBuf;

use crate::crypto;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Browser {
    Chrome,
    Edge,
    Brave,
    Chromium,
}

impl Browser {
    /// Name of the preferences file for this browser/platform combination.
    pub fn prefs_filename(&self) -> &str {
        if cfg!(target_os = "linux") {
            "Preferences"
        } else {
            "Secure Preferences"
        }
    }

    /// Default path to the preferences file for a given profile.
    pub fn prefs_path(&self, profile: &str) -> io::Result<PathBuf> {
        Ok(self.user_data_dir()?.join(profile).join(self.prefs_filename()))
    }

    /// Default path to `resources.pak` (adjacent to the browser binary).
    pub fn pak_path(&self) -> io::Result<PathBuf> {
        self.install_dir().map(|d| d.join("resources.pak"))
    }

    /// Extract the HMAC seed for this browser.
    ///
    /// - Chrome/Chromium: parse from `resources.pak` (varies per version)
    /// - Edge/Brave: 64 zero bytes
    /// - Linux: empty (vestigial protection)
    pub fn seed(&self, pak_override: Option<&PathBuf>) -> io::Result<Vec<u8>> {
        if cfg!(target_os = "linux") {
            return Ok(Vec::new());
        }

        match self {
            Self::Edge | Self::Brave => Ok(vec![0u8; 64]),
            Self::Chrome | Self::Chromium => {
                let pak = match pak_override {
                    Some(p) => p.clone(),
                    None => self.pak_path()?,
                };
                crypto::extract_seed(&pak)
            }
        }
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn user_data_dir(&self) -> io::Result<PathBuf> {
        #[cfg(target_os = "windows")]
        {
            let local_app_data = std::env::var("LOCALAPPDATA").map_err(|e| {
                io::Error::new(io::ErrorKind::NotFound, format!("LOCALAPPDATA: {e}"))
            })?;
            let base = PathBuf::from(local_app_data);
            Ok(match self {
                Self::Chrome => base.join("Google").join("Chrome").join("User Data"),
                Self::Edge => base.join("Microsoft").join("Edge").join("User Data"),
                Self::Brave => base
                    .join("BraveSoftware")
                    .join("Brave-Browser")
                    .join("User Data"),
                Self::Chromium => base.join("Chromium").join("User Data"),
            })
        }

        #[cfg(target_os = "macos")]
        {
            let home = std::env::var("HOME")
                .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("HOME: {e}")))?;
            let base = PathBuf::from(home)
                .join("Library")
                .join("Application Support");
            Ok(match self {
                Self::Chrome => base.join("Google").join("Chrome"),
                Self::Edge => base.join("Microsoft Edge"),
                Self::Brave => base.join("BraveSoftware").join("Brave-Browser"),
                Self::Chromium => base.join("Chromium"),
            })
        }

        #[cfg(target_os = "linux")]
        {
            let home = std::env::var("HOME")
                .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("HOME: {e}")))?;
            let config = PathBuf::from(home).join(".config");
            Ok(match self {
                Self::Chrome => config.join("google-chrome"),
                Self::Edge => config.join("microsoft-edge"),
                Self::Brave => config.join("BraveSoftware").join("Brave-Browser"),
                Self::Chromium => config.join("chromium"),
            })
        }
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn install_dir(&self) -> io::Result<PathBuf> {
        #[cfg(target_os = "windows")]
        {
            let program_files = std::env::var("PROGRAMFILES").map_err(|e| {
                io::Error::new(io::ErrorKind::NotFound, format!("PROGRAMFILES: {e}"))
            })?;
            let pf86 = std::env::var("PROGRAMFILES(X86)").unwrap_or_default();
            let base = PathBuf::from(&program_files);
            let base86 = PathBuf::from(&pf86);

            let candidates: Vec<PathBuf> = match self {
                Self::Chrome => vec![
                    base.join("Google").join("Chrome").join("Application"),
                    base86.join("Google").join("Chrome").join("Application"),
                ],
                Self::Edge => vec![
                    base.join("Microsoft").join("Edge").join("Application"),
                    base86.join("Microsoft").join("Edge").join("Application"),
                ],
                Self::Brave => vec![
                    base.join("BraveSoftware")
                        .join("Brave-Browser")
                        .join("Application"),
                    base86
                        .join("BraveSoftware")
                        .join("Brave-Browser")
                        .join("Application"),
                ],
                Self::Chromium => vec![
                    base.join("Chromium").join("Application"),
                    base86.join("Chromium").join("Application"),
                ],
            };

            // Find the versioned subdirectory containing resources.pak
            for candidate in &candidates {
                if let Ok(entries) = std::fs::read_dir(candidate) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() && path.join("resources.pak").exists() {
                            return Ok(path);
                        }
                    }
                }
            }

            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("could not locate {self:?} install directory"),
            ))
        }

        #[cfg(target_os = "macos")]
        {
            let app_dir = match self {
                Self::Chrome => "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/Current/Resources",
                Self::Edge => "/Applications/Microsoft Edge.app/Contents/Frameworks/Microsoft Edge Framework.framework/Versions/Current/Resources",
                Self::Brave => "/Applications/Brave Browser.app/Contents/Frameworks/Brave Browser Framework.framework/Versions/Current/Resources",
                Self::Chromium => "/Applications/Chromium.app/Contents/Frameworks/Chromium Framework.framework/Versions/Current/Resources",
            };
            let path = PathBuf::from(app_dir);
            if path.exists() {
                Ok(path)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("could not locate {self:?} at {app_dir}"),
                ))
            }
        }

        #[cfg(target_os = "linux")]
        {
            let bin_dir = match self {
                Self::Chrome => "/opt/google/chrome",
                Self::Edge => "/opt/microsoft/msedge",
                Self::Brave => "/opt/brave.com/brave",
                Self::Chromium => "/usr/lib/chromium",
            };
            let path = PathBuf::from(bin_dir);
            if path.exists() {
                Ok(path)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("could not locate {self:?} at {bin_dir}"),
                ))
            }
        }
    }
}

impl std::fmt::Display for Browser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Chrome => write!(f, "Chrome"),
            Self::Edge => write!(f, "Edge"),
            Self::Brave => write!(f, "Brave"),
            Self::Chromium => write!(f, "Chromium"),
        }
    }
}
