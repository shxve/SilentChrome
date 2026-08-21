# SilentChrome

Cross-platform Chromium extension sideloader and integrity verifier. The CLI
discovers browser profiles, selects each browser's Secure Preferences seed and
device identity, then delegates the integrity model to
[`secpref-kit`](https://github.com/shxve/secpref-kit).

## Architecture

- `browser.rs` owns Chrome, Edge, Brave, and Chromium path/seed discovery.
- `identity.rs` owns platform orchestration: Chromium-compatible machine SID
  on Windows, Hardware UUID on macOS, and the empty Linux device ID.
- `prefs.rs` owns preferences-file I/O and atomic replacement.
- `secpref-kit` owns DataPack parsing, manifests, extension IDs, JSON
  canonicalization, MACs, and preference mutations.

There is deliberately one implementation of the security-sensitive
primitives. SilentChrome is a consumer, not a fork of them.

## Usage

```text
silent-chrome install <EXT_DIR> [--browser chrome] [--profile Default]
silent-chrome uninstall <EXT_ID> [--browser chrome] [--profile Default]
silent-chrome list [--browser chrome] [--profile Default]
silent-chrome verify <EXT_ID> [--browser chrome] [--profile Default]
silent-chrome info [--browser chrome] [--profile Default]
```

Use `--pak-path` to select a specific `resources.pak`, or `--browser-path` to
select the directory containing it.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

Use only on systems you own or are explicitly authorized to test.
