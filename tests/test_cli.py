"""CLI surface: exit codes, JSON mode, human mode, stub subcommands."""

import json
from pathlib import Path

import pytest

from rerust.cli import main

from fixtures import (
    FRIDA_MATCH,
    lib_with_match,
    librhttp_like,
    make_apk,
    make_lib,
    make_pattern_db,
    rust_glue_like,
)


@pytest.fixture()
def apk(tmp_path):
    path = tmp_path / "app.apk"
    make_apk(
        path,
        {
            "lib/arm64-v8a/librhttp.so": librhttp_like(),
            "assets/data.bin": b"\x00" * 16,
        },
    )
    return str(path)


def test_inspect_json_mode(apk, capsys):
    assert main(["inspect", apk, "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["apk"] == "app.apk"
    lib = out["libs"]["lib/arm64-v8a/librhttp.so"]
    assert lib["relevance"] == "primary"
    assert ("rustls", "0.23.37") in {tuple(c) for c in lib["crates"]}


def test_inspect_human_mode(apk, capsys):
    assert main(["inspect", apk]) == 0
    out = capsys.readouterr().out
    assert "== lib/arm64-v8a/librhttp.so  [primary]" in out
    assert "rustls 0.23.37" in out
    assert "→ TLS: rustls+ring" in out


def test_inspect_missing_file_exit_2(capsys):
    assert main(["inspect", "/nonexistent/app.apk"]) == 2
    assert "not found" in capsys.readouterr().err


def test_inspect_not_a_zip_exit_2(tmp_path, capsys):
    path = tmp_path / "bogus.apk"
    path.write_bytes(b"this is not a zip file")
    assert main(["inspect", str(path)]) == 2
    assert "not an APK/zip" in capsys.readouterr().err


def test_inspect_no_rust_libs_exit_1(tmp_path, capsys):
    path = tmp_path / "plain.apk"
    make_apk(path, {"lib/arm64-v8a/libnative.so": make_lib(b"nothing to see")})
    assert main(["inspect", str(path)]) == 1
    assert "no Rust libraries found" in capsys.readouterr().out


def test_patch_forwards_to_pipeline_script(apk, monkeypatch):
    """`patch` delegates to scripts/repack_apk.py (repo checkout required).

    The pipeline itself (NDK build, patchelf, zipalign, apksigner) is
    integration territory — see test_repack.py and docs/research/
    m1_shim_repack_results.md — so here we only pin the delegation contract.
    """
    calls = []

    class Fake:
        returncode = 0

    monkeypatch.setattr(
        "rerust.cli.subprocess.run", lambda cmd, *a, **kw: (calls.append(cmd), Fake())[1]
    )
    assert main(["patch", apk, "--proxy", "http://10.0.2.2:8083"]) == 0
    cmd = calls[0]
    assert Path(cmd[0]).name.startswith("python")  # venv/uv abspath is fine
    assert cmd[1].endswith("scripts/repack_apk.py")
    assert apk in cmd
    assert cmd[cmd.index("--proxy") + 1] == "http://10.0.2.2:8083"
    assert cmd[cmd.index("--out") + 1].endswith("app.rerust.apk")

    # explicit --out is forwarded verbatim
    assert main(["patch", apk, "--proxy", "http://x:1", "--out", "/tmp/y.apk"]) == 0
    assert calls[-1][calls[-1].index("--out") + 1] == "/tmp/y.apk"


def test_frida_emits_script_to_out(tmp_path, capsys):
    db = make_pattern_db(tmp_path / "patterns")
    apk = tmp_path / "app.apk"
    data = lib_with_match()
    make_apk(apk, {"lib/arm64-v8a/librhttp.so": data})
    out = tmp_path / "agent.js"
    rc = main(["frida", str(apk), "--proxy", "http://10.0.2.2:8083",
               "--patterns", str(db), "--out", str(out)])
    assert rc == 0
    js = out.read_text()
    assert "getenv" in js and "HTTP_PROXY" in js
    assert f"offset: 0x{data.find(FRIDA_MATCH) + 4:x}" in js
    assert "Memory.patchCode" in js
    # with --out, the script goes to the file; stdout stays clean
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "agent written" in captured.err


def test_frida_default_stdout_is_the_script(tmp_path, capsys):
    db = make_pattern_db(tmp_path / "patterns")
    apk = tmp_path / "app.apk"
    make_apk(apk, {"lib/arm64-v8a/librhttp.so": lib_with_match()})
    assert main(["frida", str(apk), "--proxy", "http://10.0.2.2:8083", "--patterns", str(db)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("/**")          # header first — pipe-friendly
    assert "'use strict';" in out


def test_frida_list_is_a_dry_run(tmp_path, capsys):
    db = make_pattern_db(tmp_path / "patterns")
    apk = tmp_path / "app.apk"
    data = lib_with_match()
    make_apk(apk, {"lib/arm64-v8a/librhttp.so": data})
    assert main(["frida", str(apk), "--proxy", "http://10.0.2.2:8083",
                 "--patterns", str(db), "--list"]) == 0
    out = capsys.readouterr().out
    assert "test-force-ok" in out
    assert f"0x{data.find(FRIDA_MATCH) + 4:x}" in out
    assert "getenv" not in out            # no JS in dry-run output


def test_frida_no_db_match_still_emits_with_warning(tmp_path, capsys):
    db = make_pattern_db(tmp_path / "patterns")
    apk = tmp_path / "app.apk"
    make_apk(apk, {"lib/arm64-v8a/libglue.so": rust_glue_like()})
    out = tmp_path / "agent.js"
    assert main(["frida", str(apk), "--proxy", "http://10.0.2.2:8083",
                 "--patterns", str(db), "--out", str(out)]) == 0
    js = out.read_text()
    assert "env+observe only" in js
    assert "getenv" in js
    assert "0x" not in js.split("PATCHES = [")[1].split("]")[0]  # no patch entries


def test_frida_missing_patterns_dir_degrades(tmp_path, capsys):
    apk = tmp_path / "app.apk"
    make_apk(apk, {"lib/arm64-v8a/libglue.so": rust_glue_like()})
    rc = main(["frida", str(apk), "--proxy", "http://10.0.2.2:8083",
               "--patterns", str(tmp_path / "nope"), "--out", str(tmp_path / "a.js")])
    assert rc == 0
    assert "pattern DB dir not found" in capsys.readouterr().err


def test_frida_input_errors(tmp_path, capsys):
    assert main(["frida", "/nonexistent/app.apk", "--proxy", "http://x:1"]) == 2
    bogus = tmp_path / "bogus.apk"
    bogus.write_bytes(b"not a zip")
    assert main(["frida", str(bogus), "--proxy", "http://x:1"]) == 2
    apk = tmp_path / "app.apk"
    make_apk(apk, {"lib/arm64-v8a/libnative.so": make_lib(b"no rust")})
    assert main(["frida", str(apk), "--proxy", "http://x:1"]) == 1
    assert main(["frida", str(apk), "--proxy", "nonsense"]) == 2
    assert "not found" in capsys.readouterr().err
