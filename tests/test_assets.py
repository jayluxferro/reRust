"""Asset resolution: repo checkout (dev) vs packaged wheel assets (installed).

The wheel path is faked at the seam assets.py defines: `assets.files` (the
importlib.resources entry point) is pointed at a fake site-packages tree with
rerust/assets/{shim,patterns}, and assets.__file__ is moved there so the
repo-checkout detection (parents[2]) lands in a dir with no patterns/.
(importlib.resources itself follows the loader, not __path__, so patching
__path__ alone does nothing — the end-to-end packaged case is covered by the
uv tool install smoke instead.)
"""

import pytest
from pathlib import Path

from rerust import assets

from fixtures import PATTERN_YAML


@pytest.fixture()
def fake_installed(tmp_path, monkeypatch):
    """A fake site-packages install of rerust WITH assets, no repo around."""
    pkg = tmp_path / "site-packages" / "rerust"
    (pkg / "assets" / "patterns").mkdir(parents=True)
    (pkg / "assets" / "patterns" / "fake_aarch64.yaml").write_text(PATTERN_YAML)
    (pkg / "assets" / "shim").mkdir(parents=True)
    (pkg / "assets" / "shim" / "build.sh").write_text("#!/bin/sh\nexit 0\n")
    (pkg / "assets" / "shim" / "librerust.c").write_text("/* fake */\n")

    monkeypatch.setattr(assets, "files", lambda _pkg: Path(pkg))
    monkeypatch.setattr(assets, "__file__", str(pkg / "assets.py"))
    # cache under tmp so the test never touches the user's ~/.cache
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    return pkg


class TestRepoCheckout:
    def test_patterns_dir_prefers_repo(self):
        # Running inside the repo: parents[2]/patterns exists and wins.
        d = assets.patterns_dir()
        assert d is not None
        assert d.name == "patterns"
        assert any(f.name.endswith(".yaml") for f in d.glob("*.yaml"))

    def test_extract_shim_sources_prefers_repo(self, tmp_path):
        dest = tmp_path / "shim-out"
        assert assets.extract_shim_sources(dest) == dest
        assert (dest / "build.sh").is_file()
        assert (dest / "librerust.c").is_file()


class TestInstalledWheel:
    def test_patterns_fall_back_to_packaged(self, fake_installed):
        d = assets.patterns_dir()
        assert d is not None
        assert d.is_dir()
        # resolved OUTSIDE the fake site-packages (cache copy), but with the
        # packaged content — load_patterns must be able to read it
        from rerust.trust import load_patterns

        entries = load_patterns(d)
        assert any(e.crate == "rustls" for e in entries)

    def test_patterns_cache_is_versioned(self, fake_installed, tmp_path):
        assets.patterns_dir()
        versioned = tmp_path / "cache" / "rerust"
        assert (versioned / assets.__version__ / "patterns").is_dir()

    def test_shim_sources_extract_from_packaged(self, fake_installed, tmp_path):
        dest = tmp_path / "shim-out"
        assert assets.extract_shim_sources(dest) == dest
        assert (dest / "build.sh").is_file()
        assert (dest / "librerust.c").is_file()

    def test_no_assets_anywhere_returns_none(self, tmp_path, monkeypatch):
        # Installed layout WITHOUT the assets trees (e.g. a hand-rolled
        # package dir): both resolution steps must come up empty, not crash.
        pkg = tmp_path / "site-packages" / "rerust"
        pkg.mkdir(parents=True)
        monkeypatch.setattr(assets, "files", lambda _pkg: Path(pkg))
        monkeypatch.setattr(assets, "__file__", str(pkg / "assets.py"))
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
        assert assets.patterns_dir() is None
        assert assets.extract_shim_sources(tmp_path / "x") is None


class TestDevWrapper:
    @pytest.mark.skipif(assets.repo_dir("src") is None, reason="repo checkout required")
    def test_scripts_repack_apk_delegates_to_pipeline(self):
        # The wrapper must stay a thin delegation — read its source and pin
        # the contract (no second copy of the orchestration sneaks back in).
        src = (
            assets.repo_dir("src").parent / "scripts" / "repack_apk.py"
        ).read_text()
        assert "from rerust.pipeline import main" in src
        assert "repack_apk(" not in src  # the old orchestration is gone
