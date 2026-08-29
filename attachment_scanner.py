"""
attachment_scanner.py
----------------------
Static, offline heuristics for email attachments (no sandboxing/
execution of anything -- this only inspects filenames/bytes).

Flags:
  - dangerous extensions (.exe, .scr, .js, .vbs, .bat, .cmd, .jar, .msi, .ps1)
  - macro-enabled Office formats (.docm, .xlsm, .pptm)
  - double extensions ("invoice.pdf.exe")
  - archive files that could hide payloads (.zip, .rar, .7z, .iso)
  - computes SHA-256 so it can be checked later against a hash blocklist
    or pasted into VirusTotal by the analyst
"""

import hashlib
import re

DANGEROUS_EXT = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".jar", ".msi",
    ".ps1", ".com", ".pif", ".lnk", ".hta", ".wsf",
}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".iso", ".img"}

DOUBLE_EXT_REGEX = re.compile(r"\.\w{2,5}\.\w{2,5}$")


def scan_attachment(filename: str, content: bytes = b""):
    lower = filename.lower()
    flags = []

    for ext in DANGEROUS_EXT:
        if lower.endswith(ext):
            flags.append(f"Executable/script extension ({ext}) — high risk if run")
    for ext in MACRO_EXT:
        if lower.endswith(ext):
            flags.append(f"Macro-enabled Office document ({ext}) — common malware dropper")
    for ext in ARCHIVE_EXT:
        if lower.endswith(ext):
            flags.append(f"Archive file ({ext}) — may conceal an executable payload")
    if DOUBLE_EXT_REGEX.search(lower) and not lower.endswith((".tar.gz", ".tar.bz2")):
        flags.append("Double extension detected — classic disguise trick (e.g. invoice.pdf.exe)")

    sha256 = hashlib.sha256(content).hexdigest() if content else None

    risk = "high" if any("high risk" in f or "dropper" in f for f in flags) else \
           ("medium" if flags else "low")

    return {
        "filename": filename,
        "sha256": sha256,
        "size_bytes": len(content),
        "risk_flags": flags,
        "risk_level": risk,
    }


def scan_all(attachments: list):
    """attachments: list of (filename, content_bytes) tuples."""
    results = [scan_attachment(name, content) for name, content in attachments]
    return results


def summarize(results):
    return {
        "total_attachments": len(results),
        "high_risk": sum(1 for r in results if r["risk_level"] == "high"),
        "medium_risk": sum(1 for r in results if r["risk_level"] == "medium"),
    }
