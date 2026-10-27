"""Lab settings for the multi-machine smoke tests, read from the environment.

These harnesses drive real remote machines over SSH. Nothing about the lab is hard-coded:
set the variables below (see docs/verification.md) before running them.
"""
import os
from pathlib import Path

DEFAULT_BINARY = str(Path(__file__).resolve().parents[1] / "target/debug/omabridge")


def lab(name, default=None):
    value = os.environ.get(f"OMABRIDGE_LAB_{name}", default)
    if value is None:
        raise SystemExit(f"set OMABRIDGE_LAB_{name} to run this lab test")
    return value


def binary():
    return os.environ.get("OMABRIDGE_BINARY", DEFAULT_BINARY)
