"""sdk.py — discovery order and loud failures."""

import pytest

from rerust import sdk


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    for var in ("ANDROID_SDK_ROOT", "ANDROID_HOME", "ANDROID_NDK", "ANDROID_NDK_HOME"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(sdk.Path, "home", lambda: tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sdk.shutil, "which", lambda _: None)


def test_env_var_wins(monkeypatch, tmp_path):
    explicit = tmp_path / "explicit-sdk"
    (explicit / "platform-tools").mkdir(parents=True)
    monkeypatch.setenv("ANDROID_SDK_ROOT", str(explicit))
    assert sdk.find_sdk() == explicit


def test_macos_studio_default(tmp_path):
    studio = tmp_path / "Library" / "Android" / "sdk"
    (studio / "platform-tools").mkdir(parents=True)
    (studio / "build-tools").mkdir()
    assert sdk.find_sdk() == studio


def test_local_properties_beats_defaults(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    custom = tmp_path / "custom-sdk"
    custom.mkdir()
    (proj / "local.properties").write_text(f"sdk.dir={custom}\n")
    studio = tmp_path / "Library" / "Android" / "sdk"
    studio.mkdir(parents=True)
    monkeypatched_cwd = proj
    import os
    os.chdir(monkeypatched_cwd)
    try:
        assert sdk.find_sdk() == custom
    finally:
        os.chdir(tmp_path)


def test_adb_parent_with_sdk_shape(tmp_path, monkeypatch):
    fake = tmp_path / "toolsdk" / "platform-tools" / "adb"
    fake.parent.mkdir(parents=True)
    (tmp_path / "toolsdk" / "build-tools").mkdir()
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setattr(sdk.shutil, "which", lambda _: str(fake))
    assert sdk.find_sdk() == tmp_path / "toolsdk"


def test_adb_parent_without_sdk_shape_rejected(tmp_path, monkeypatch):
    fake = tmp_path / "bin" / "adb"  # e.g. homebrew: parent.parent has no platform-tools
    fake.parent.mkdir(parents=True)
    fake.write_text("#!/bin/sh\n")
    monkeypatch.setattr(sdk.shutil, "which", lambda _: str(fake))
    with pytest.raises(SystemExit):
        sdk.find_sdk()


def test_missing_sdk_exits_loud():
    with pytest.raises(SystemExit, match="ANDROID_SDK_ROOT"):
        sdk.find_sdk()


def test_ndk_newest_version_dir(tmp_path):
    root = tmp_path / "sdk"
    (root / "ndk" / "26.1.1").mkdir(parents=True)
    (root / "ndk" / "28.2.2").mkdir()
    assert sdk.find_ndk(root).name == "28.2.2"


def test_missing_ndk_exits_loud(tmp_path):
    root = tmp_path / "empty-sdk"
    root.mkdir()
    with pytest.raises(SystemExit, match="ANDROID_NDK"):
        sdk.find_ndk(root)
