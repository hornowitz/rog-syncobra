import importlib.util
import sys
import types
from collections import deque
from pathlib import Path

if "xxhash" not in sys.modules:
    class _DummyHash:
        def update(self, _data):
            return None

        def hexdigest(self):
            return "dummy"

    sys.modules["xxhash"] = types.SimpleNamespace(xxh64=lambda: _DummyHash())

if "tqdm" not in sys.modules:
    tqdm_module = types.ModuleType("tqdm")

    class _DummyTqdm:
        def __init__(self, *_args, **_kwargs):
            pass

        def update(self, *_args, **_kwargs):
            pass

        def close(self):
            pass

    def _tqdm(*_args, **_kwargs):
        return _DummyTqdm()

    tqdm_module.tqdm = _tqdm
    sys.modules["tqdm"] = tqdm_module

if "requests" not in sys.modules:
    sys.modules["requests"] = types.SimpleNamespace(Session=lambda: types.SimpleNamespace())

MODULE_PATH = Path(__file__).with_name("rog-syncobra.py")
SPEC = importlib.util.spec_from_file_location("rog_syncobra", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_exif_sort_configures_stay_open_ready(monkeypatch, tmp_path):
    instances = []

    class DummyStdout:
        def __init__(self):
            self.lines = deque()
            self.history = []

        def push_ready(self):
            self.lines.append("{ready}\n")

        def readline(self):
            if not self.lines:
                raise AssertionError("No output queued for exiftool mock")
            line = self.lines.popleft()
            self.history.append(line)
            return line

    class DummyStdin:
        def __init__(self, stdout):
            self.stdout = stdout
            self.writes: list[str] = []

        def write(self, data: str):
            self.writes.append(data)
            ready_count = data.count("-echo3\n")
            for _ in range(ready_count):
                self.stdout.push_ready()
            return len(data)

        def flush(self):
            return None

    class DummyProc:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs
            self.stdout = DummyStdout()
            self.stdin = DummyStdin(self.stdout)

        def communicate(self):
            return ("", "")

    def fake_popen(*args, **kwargs):
        proc = DummyProc(*args, **kwargs)
        instances.append(proc)
        return proc

    monkeypatch.setattr(MODULE.subprocess, "Popen", fake_popen)

    (tmp_path / "Screenshot_20240924.jpg").write_bytes(b"")
    args = types.SimpleNamespace(
        debug=False,
        year_month_sort=False,
        skip_marker=None,
        recursive=False,
        whatsapp=False,
        dry_run=False,
    )

    result = MODULE.exif_sort(str(tmp_path), str(tmp_path), args)
    assert result is True
    assert instances, "exiftool worker was not started"

    proc = instances[0]
    assert proc.stdin.writes[0].startswith("-echo3\n{ready}\n")
    assert proc.stdout.history[0].strip() == "{ready}"
    total_ready = sum(write.count("-echo3\n{ready}\n") for write in proc.stdin.writes)
    assert len(proc.stdout.history) == total_ready
    for write in proc.stdin.writes[1:]:
        if "-execute\n" not in write:
            continue
        assert "-echo3\n{ready}\n-execute\n" in write
