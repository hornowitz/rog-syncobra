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


def test_raw_dedupe_passes_delete_within(monkeypatch, tmp_path):
    calls: dict[str, object] = {}

    def fake_dedupe(paths, *, dry_run, strip_metadata, delete_within=None, **kwargs):
        calls.update(
            {
                "paths": paths,
                "dry_run": dry_run,
                "strip_metadata": strip_metadata,
                "delete_within": delete_within,
                "extra_kwargs": kwargs,
            }
        )

    monkeypatch.setattr(MODULE, "xxdedupi_dedupe", fake_dedupe)

    src = tmp_path / "src"
    dest = tmp_path / "dest"
    src.mkdir()
    dest.mkdir()

    MODULE.raw_dedupe(str(src), str(dest), dry_run=False)

    assert calls["delete_within"] == [str(src.resolve())]
    assert calls["strip_metadata"] == "both"
    assert calls["paths"] == [str(dest.resolve()), str(src.resolve())]
