"""Pipeline units: SDK/NDK discovery, keystore, validation, exit codes.

The real NDK/patchelf/zipalign/apksigner flow is integration territory
(docs/research/m1_shim_repack_results.md) — these tests pin the contracts
around it without invoking a toolchain.
"""

import subprocess

import pytest

from rerust import pipeline

from fixtures import make_lib


class TestSdkNdkDiscovery:
    def test_find_sdk_from_env(self, tmp_path, monkeypatch):
        sdk = tmp_path / "Sdk"
        sdk.mkdir()
        monkeypatch.setenv("ANDROID_SDK_ROOT", str(sdk))
        monkeypatch.delenv("ANDROID_HOME", raising=False)
        assert pipeline.find_sdk() == str(sdk)

    def test_find_sdk_missing_raises(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)
        monkeypatch.delenv("ANDROID_HOME", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path))  # no ~/Android/Sdk either
        with pytest.raises(FileNotFoundError):
            pipeline.find_sdk()

    def test_find_ndk_prefers_newest(self, tmp_path, monkeypatch):
        sdk = tmp_path / "Sdk"
        for v in ("27.0.0", "28.0.1"):
            (sdk / "ndk" / v).mkdir(parents=True)
        monkeypatch.delenv("ANDROID_NDK", raising=False)
        monkeypatch.delenv("ANDROID_NDK_HOME", raising=False)
        assert pipeline.find_ndk(str(sdk)) == str(sdk / "ndk" / "28.0.1")

    def test_find_ndk_env_override_wins(self, tmp_path, monkeypatch):
        ndk = tmp_path / "my-ndk"
        ndk.mkdir()
        monkeypatch.setenv("ANDROID_NDK", str(ndk))
        assert pipeline.find_ndk(str(tmp_path)) == str(ndk)

    def test_build_tools_default_is_lazy(self, tmp_path, monkeypatch):
        # --shim runs must not need an SDK; find_sdk is only called for the
        # default build-tools. Pin the lazy resolution shape here.
        monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)
        monkeypatch.delenv("ANDROID_HOME", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path))
        with pytest.raises(FileNotFoundError):
            pipeline.find_sdk()


class TestKeystore:
    def test_existing_keystore_untouched(self, tmp_path, monkeypatch):
        ks = tmp_path / "debug.keystore"
        ks.write_bytes(b"fake")
        monkeypatch.setattr(pipeline.subprocess, "run",
                            lambda *a, **kw: pytest.fail("keytool must not run"))
        assert pipeline.ensure_keystore(ks) == ks

    def test_missing_keystore_generated(self, tmp_path, monkeypatch):
        ks = tmp_path / "android" / "debug.keystore"

        def fake_run(cmd, **kw):
            assert cmd[0] == "keytool"
            assert str(ks) in cmd
            ks.parent.mkdir(parents=True, exist_ok=True)
            ks.write_bytes(b"generated")
            return subprocess.CompletedProcess(cmd, 0)

        monkeypatch.setattr(pipeline.subprocess, "run", fake_run)
        assert pipeline.ensure_keystore(ks) == ks
        assert ks.exists()


class TestRunPatchValidation:
    """Config errors exit 2 BEFORE any tool is invoked (exit-code contract)."""

    def test_needs_a_redirect_source(self, tmp_path, capsys):
        apk = tmp_path / "app.apk"
        apk.write_bytes(b"x")  # exists; validation must fail before reading it
        rc = pipeline.run_patch(_ns(apk=str(apk)))
        assert rc == 2
        assert "need --proxy" in capsys.readouterr().err

    def test_redirect_all_needs_hook(self, tmp_path, capsys):
        rc = pipeline.run_patch(_ns(apk=str(tmp_path / "a.apk"), proxy="http://x:1",
                                    redirect="all"))
        assert rc == 2
        assert "--hook-connect" in capsys.readouterr().err

    def test_missing_apk_exit_2(self, tmp_path, capsys):
        rc = pipeline.run_patch(_ns(apk=str(tmp_path / "nope.apk"), proxy="http://x:1"))
        assert rc == 2
        assert "not found" in capsys.readouterr().err

    def test_missing_shim_sources_exit_2(self, tmp_path, capsys, monkeypatch):
        # No repo shim/ and no packaged assets: building must fail loudly with
        # a pointer at --shim, not with an NDK traceback.
        monkeypatch.setattr(pipeline.assets, "extract_shim_sources", lambda dest: None)
        monkeypatch.setenv("ANDROID_NDK", str(tmp_path / "ndk"))  # exists → find_ndk ok
        (tmp_path / "ndk").mkdir()
        apk = tmp_path / "app.apk"
        apk.write_bytes(b"\x00")
        rc = pipeline.run_patch(_ns(apk=str(apk), proxy="http://x:1",
                                    workdir=str(tmp_path / "work")))
        assert rc == 2
        assert "shim sources not found" in capsys.readouterr().err

    def test_repack_failure_exit_1(self, tmp_path, capsys, monkeypatch):
        # Existing-but-garbage APK → repack_apk raises BadZipFile → 1.
        apk = tmp_path / "app.apk"
        apk.write_bytes(b"not a zip")
        shim = tmp_path / "librerust.so"
        shim.write_bytes(b"\x7fELF-fake-shim")  # plain shim (no hook marker)
        rc = pipeline.run_patch(_ns(apk=str(apk), proxy="http://x:1",
                                    shim=str(shim), workdir=str(tmp_path / "work")))
        assert rc == 1
        assert "error:" in capsys.readouterr().err


def _ns(**kw):
    """A run_patch namespace with the same defaults argparse would produce."""
    import argparse

    defaults = dict(
        apk=None, proxy=None, out=None, shim=None, no_bake=False, also_patch=[],
        hook_connect=None, hook_port=443, hook_timeout=1500, redirect=None,
        ndk=None, build_tools=None, workdir="/tmp/rerust-work", no_trust=False,
        patterns=None, require_trust=False,
    )
    defaults.update(kw)
    return argparse.Namespace(**defaults)
