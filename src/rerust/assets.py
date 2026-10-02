"""Asset resolution: repo checkout (dev) vs packaged wheel assets (installed).

`rerust` carries two asset trees that historically lived only in the repo:

- ``patterns/``  the trust pattern DB (yaml, read by trust.load_patterns)
- ``shim/``      the env-proxy shim sources (build.sh + librerust.c, driven by
                 pipeline.build_shim through the Android NDK)

In a repo checkout those dirs sit next to the package (``parents[2]``); in an
installed wheel they are force-included at build time (pyproject
``[tool.hatch.build.targets.wheel.force-include]``) as
``rerust/assets/{shim,patterns}``.

Resolution order, everywhere:
  1. repo checkout — dev mode: W3's yaml edits and the shim sources are picked
     up live, exactly as before packaging existed.
  2. packaged assets — copied into a versioned cache dir
     (``$XDG_CACHE_HOME/rerust/<version>/``, default ``~/.cache``) because
     importlib.resources only guarantees a real filesystem path INSIDE
     ``as_file()``'s context (a zip-installed package extracts to a temp dir
     that dies with the context), while callers need a stable path
     (load_patterns) or a directory a shell script can compile from
     (build.sh). Keyed by ``__version__`` so a wheel upgrade refreshes it.
     The copy is redone on every resolution — ~30 KB, and immune to stale
     caches after a partial upgrade.

Shim sources for an actual build go through extract_shim_sources() into the
pipeline's workdir (always refreshed per run) — two small files; anything
cleverer would be staleness risk for zero gain.
"""

from __future__ import annotations

import os
import shutil
from importlib.resources import as_file, files
from pathlib import Path

from . import __version__


def _cache_root() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base) / "rerust" / __version__


def repo_dir(name: str) -> Path | None:
    """The repo's ``<name>/`` if this is a checkout (dev mode), else None.

    Relies on src-layout: <repo>/src/rerust/assets.py -> parents[2] = <repo>.
    """
    candidate = Path(__file__).resolve().parents[2] / name
    return candidate if candidate.is_dir() else None


def _packaged_tree(name: str, dest: Path) -> Path | None:
    """Copy packaged ``rerust/assets/<name>`` into dest; None if not packaged."""
    try:
        root = files("rerust").joinpath("assets", name)
        with as_file(root) as p:
            if not p.is_dir():
                return None
            shutil.copytree(p, dest, dirs_exist_ok=True)
            return dest
    except (ModuleNotFoundError, NotADirectoryError, FileNotFoundError):
        return None


def patterns_dir() -> Path | None:
    """Trust pattern DB dir: repo checkout first, packaged copy second, else None."""
    repo = repo_dir("patterns")
    if repo is not None:
        return repo
    return _packaged_tree("patterns", _cache_root() / "patterns")


def extract_shim_sources(dest: Path) -> Path | None:
    """Copy the shim sources (build.sh, librerust.c) into ``dest``; None if
    neither a repo checkout nor packaged assets provide them."""
    src = repo_dir("shim")
    if src is not None:
        shutil.copytree(src, dest, dirs_exist_ok=True)
        return dest
    return _packaged_tree("shim", dest)
