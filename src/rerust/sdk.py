"""Android SDK/NDK discovery — works for installed tools and checkouts alike.

Resolution order (first hit wins, every miss is silent, the final failure is loud):
  1. $ANDROID_SDK_ROOT / $ANDROID_HOME (explicit user intent)
  2. sdk.dir from a local.properties in ./ or ../ (Android/Flutter project checkouts)
  3. parent directory of the `adb` on PATH, if it looks like an SDK (has
     platform-tools/ and build-tools/ — guards against Homebrew/shim adb)
  4. platform defaults:
       macOS:   ~/Library/Android/sdk   (Android Studio default) and ~/Android/Sdk
       Linux:   ~/Android/Sdk, /opt/android-sdk
       Windows: %LOCALAPPDATA%/Android/Sdk

NDK: $ANDROID_NDK / $ANDROID_NDK_HOME, else the newest $SDK/ndk/* (sdkmanager's
standard location). Fallbacks stay loud: a missing SDK/NDK is a configuration
problem, not something to paper over.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def _looks_like_sdk(p: Path) -> bool:
    return p.is_dir() and (p / "platform-tools").is_dir() and (p / "build-tools").is_dir()


def _from_env() -> Path | None:
    for var in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        v = os.environ.get(var)
        if v and Path(v).is_dir():
            return Path(v)
    return None


def _from_local_properties() -> Path | None:
    # Flutter/Android projects carry sdk.dir in local.properties
    for base in (Path.cwd(), Path.cwd().parent):
        f = base / "local.properties"
        if f.is_file():
            for line in f.read_text(errors="ignore").splitlines():
                if line.startswith("sdk.dir="):
                    v = line.split("=", 1)[1].strip().replace("\\:", ":").rstrip("/")
                    if v and Path(v).is_dir():
                        return Path(v)
    return None


def _from_adb_parent() -> Path | None:
    adb = shutil.which("adb")
    if not adb:
        return None
    p = Path(adb).resolve().parent.parent  # <sdk>/platform-tools/adb
    return p if _looks_like_sdk(p) else None


def _platform_defaults() -> Path | None:
    home = Path.home()
    cands = [
        home / "Library" / "Android" / "sdk",   # Android Studio on macOS (the default)
        home / "Android" / "Sdk",               # Android Studio on Linux / manual macOS
        Path("/opt/android-sdk"),
        Path(os.environ.get("LOCALAPPDATA", "")) / "Android" / "Sdk" if os.environ.get("LOCALAPPDATA") else None,
    ]
    for c in cands:
        if c and c.is_dir():
            return c
    return None


def find_sdk() -> Path:
    for probe in (_from_env, _from_local_properties, _from_adb_parent, _platform_defaults):
        p = probe()
        if p:
            return p
    sys.exit(
        "Android SDK not found. Set ANDROID_SDK_ROOT (or ANDROID_HOME), install "
        "Android Studio (~/Library/Android/sdk is picked up automatically), or run "
        "from inside an Android/Flutter project with local.properties."
    )


def find_ndk(sdk: Path | None = None) -> Path:
    for var in ("ANDROID_NDK", "ANDROID_NDK_HOME"):
        v = os.environ.get(var)
        if v and Path(v).is_dir():
            return Path(v)
    base = (sdk or find_sdk()) / "ndk"
    if base.is_dir():
        cands = sorted(x for x in base.iterdir() if x.is_dir())
        if cands:
            return cands[-1]  # newest installed version
    sys.exit(
        "Android NDK not found. Set ANDROID_NDK, or install one under "
        "$ANDROID_SDK_ROOT/ndk (sdkmanager --install \"ndk;latest\")."
    )


def latest_build_tools(sdk: Path | None = None) -> Path | None:
    """Newest $SDK/build-tools/* — for zipalign/apksigner."""
    base = (sdk or find_sdk()) / "build-tools"
    if base.is_dir():
        cands = sorted(x for x in base.iterdir() if x.is_dir())
        if cands:
            return cands[-1]
    return None


def which(tool: str) -> str:
    """A tool name -> absolute path via PATH (documented escape hatch)."""
    p = shutil.which(tool)
    if not p:
        sys.exit(f"required tool not on PATH: {tool}")
    return p


_ = subprocess  # reserved for future sdkmanager queries
