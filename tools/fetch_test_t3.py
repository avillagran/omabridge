#!/usr/bin/env python3
"""Fetch a pinned official x86_64 T3 CLI only into the isolated test-tools directory."""
import hashlib
import json
from pathlib import Path
import tarfile
import urllib.request

VERSION = "0.0.46-nightly.20261013.3042"
ASSET = f"t3-{VERSION}-linux-x64.tar.gz"
BASE = f"https://github.com/pingdotgg/t3code/releases/download/v{VERSION}"
ROOT = Path(__file__).resolve().parents[1] / ".tools" / "t3" / VERSION


def fetch(url, path):
    with urllib.request.urlopen(url, timeout=60) as response, path.open("wb") as output:
        while chunk := response.read(1024 * 1024):
            output.write(chunk)


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    sums = ROOT / "SHA256SUMS"
    archive = ROOT / ASSET
    fetch(f"{BASE}/SHA256SUMS", sums)
    expected = next(line.split()[0] for line in sums.read_text().splitlines() if line.split()[-1].lstrip("*") == ASSET)
    if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        fetch(f"{BASE}/{ASSET}", archive)
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == expected, "T3 release checksum mismatch"
    with tarfile.open(archive) as tar:
        tar.extractall(ROOT / "unpacked", filter="data")
    manifest = {"version": VERSION, "asset": ASSET, "url": f"{BASE}/{ASSET}", "sha256": expected}
    (ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()
