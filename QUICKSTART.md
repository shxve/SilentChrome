# SilentChrome — Quickstart

Silently install unpacked Chromium extensions by forging Secure Preferences HMACs. No GUI interaction, no `chrome://extensions`, no `--load-extension` flag. The extension loads on the next browser launch as if it had already been installed via Developer Mode.

## Build

### Requirements

- Rust toolchain (edition 2024 — rustc 1.85+)
- For Windows cross-compilation from Linux: [cargo-xwin](https://github.com/rust-cross/cargo-xwin)

### Windows (cross-compile from Linux)

```bash
cargo xwin build --release --target x86_64-pc-windows-msvc
```

Binary: `target/x86_64-pc-windows-msvc/release/silent-chrome.exe`

### Native (Linux / macOS)

```bash
cargo build --release
```

Binary: `target/release/silent-chrome`

## Usage

### 1. Prepare your extension

Your extension directory must contain a valid `manifest.json` (MV3 recommended). Example minimal structure:

```
my-extension/
├── manifest.json
├── background.js
└── content.js
```

### 2. Kill the browser

The browser **must not be running** when you modify its preferences.

```bash
# Windows
taskkill /f /im chrome.exe

# macOS
killall "Google Chrome"

# Linux
pkill -f chrome
```

### 3. Install the extension

```bash
silent-chrome install <path-to-extension-dir>
```

Example output:

```
[*] browser:    Chrome
[*] profile:    Default
[*] prefs:      C:\Users\user\AppData\Local\Google\Chrome\User Data\Default\Secure Preferences
[*] seed:       64 bytes
[*] device_id:  S-1-5-21-1650828501-840997873-2917006960
[*] extension:  C:\tools\my-extension
[+] installed:  abcdefghijklmnopabcdefghijklmnop
[+] mac:        A1B2C3...
[+] super_mac:  D4E5F6...
```

### 4. Launch the browser

Start Chrome normally. The extension loads with Developer Mode enabled.

### 5. Verify (optional)

```bash
silent-chrome verify <extension-id>
```

```
extension MAC:   PASS
dev_mode MAC:    PASS
account dev MAC: PASS
super_mac:       PASS
[+] all MACs valid
```

## Options

```
silent-chrome install <EXT_DIR> [OPTIONS]
  -b, --browser <chrome|edge|brave|chromium>   Target browser [default: chrome]
  -p, --profile <NAME>                         Profile name [default: Default]
      --pak-path <PATH>                         Override resources.pak path
      --browser-path <PATH>                     Directory containing resources.pak

silent-chrome uninstall <EXT_ID> [OPTIONS]
silent-chrome list [OPTIONS]
silent-chrome info [OPTIONS]
silent-chrome verify <EXT_ID> [OPTIONS]
```

All subcommands accept `--browser` and `--profile`.

## Multi-browser support

| Browser  | Seed source                         | Notes                    |
|----------|-------------------------------------|--------------------------|
| Chrome   | Extracted from `resources.pak`      | Seed varies per version  |
| Edge     | 64 zero bytes                       |                          |
| Brave    | 64 zero bytes                       |                          |
| Chromium | Extracted from `resources.pak`      |                          |

```bash
silent-chrome install -b edge C:\tools\my-extension
silent-chrome install -b brave C:\tools\my-extension
```

## Extension ID

If your extension's `manifest.json` contains a `key` field (base64-encoded public key), the extension ID is derived from that key and remains stable regardless of the extension's path on disk. Without a `key`, the ID is derived from the absolute path (UTF-16-LE on Windows, UTF-8 elsewhere) and changes if you move the extension directory.

## Troubleshooting

**Extension doesn't load:**
- Confirm the browser was fully killed before running `install`.
- Run `silent-chrome verify <id>` — all four integrity checks should show PASS.
- Check that the extension path in the preferences matches the actual directory.

**"no 64-byte resource found":**
- The `resources.pak` file doesn't match the expected DataPack v5 format, or Chrome updated and the seed moved. Use `--pak-path` to point to the correct file.

**"preferences file not found":**
- The profile name might differ. Use `--profile "Profile 1"` or check the `User Data` directory for available profile folders.

**Developer Mode warning bar:**
- This is expected — Chrome shows a warning banner for unpacked extensions. It does not prevent the extension from running.
