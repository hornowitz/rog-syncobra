import importlib.util
import os
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("rog-syncobra.py")
SPEC = importlib.util.spec_from_file_location("rog_syncobra_watch", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_resolve_logfile_env_override(monkeypatch, tmp_path):
    custom = tmp_path / "custom.log"
    monkeypatch.setenv("ROG_SYNCOBRA_LOGFILE", str(custom))
    assert MODULE._resolve_logfile() == os.path.abspath(custom)

    monkeypatch.setenv("ROG_SYNCOBRA_LOGFILE", "")
    assert MODULE._resolve_logfile() is None

    monkeypatch.delenv("ROG_SYNCOBRA_LOGFILE", raising=False)
    assert MODULE._resolve_logfile() == MODULE.DEFAULT_LOGFILE


def test_wait_for_change_passes_all_inputdirs(monkeypatch):
    captured: dict[str, list[str]] = {}

    class DummyResult:
        def __init__(self, stdout: str) -> None:
            self.stdout = stdout

    def fake_run(cmd, capture_output, text, check):  # noqa: D401 - signature matches subprocess.run
        captured["cmd"] = cmd
        return DummyResult("/watch/two/file.jpg|CLOSE_WRITE\n")

    monkeypatch.setattr(MODULE.subprocess, "run", fake_run)
    path = MODULE._wait_for_change(["/watch/one", "/watch/two"])

    assert captured["cmd"] == [
        "inotifywait",
        "-r",
        "-e",
        "close_write",
        "--format",
        "%w%f|%e",
        "/watch/one",
        "/watch/two",
    ]
    assert path == "/watch/two/file.jpg"
