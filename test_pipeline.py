import importlib.util
import threading
from types import SimpleNamespace
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("rog-syncobra.py")
SPEC = importlib.util.spec_from_file_location("rog_syncobra_pipeline", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_run_pipelines_sequential(monkeypatch):
    calls: list[tuple[str, str]] = []

    def fake_pipeline(args, src):
        calls.append((src, threading.current_thread().name))

    monkeypatch.setattr(MODULE, "pipeline", fake_pipeline)

    args = SimpleNamespace(move2targetdir=None, dry_run=False)
    sources = ["/path/one", "/path/two", "/path/three"]

    MODULE._run_pipelines(args, sources)

    assert [src for src, _ in calls] == sources
    thread_names = {name for _, name in calls}
    assert thread_names == {threading.current_thread().name}
