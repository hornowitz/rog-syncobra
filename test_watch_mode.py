import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

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


def test_watchdog_watcher_schedules_and_emits(monkeypatch):
    scheduled: list[tuple[str, bool]] = []

    class DummyObserver:
        def __init__(self) -> None:
            self.started = False

        def schedule(self, handler, path, recursive):
            scheduled.append((path, recursive))
            # Expose handler so we can emit events manually during the test.
            self.handler = handler

        def start(self):
            self.started = True

        def stop(self):
            self.started = False

        def join(self, timeout=None):
            return None

    class DummyBase:
        def __init__(self) -> None:
            pass

    monkeypatch.setattr(MODULE, "Observer", DummyObserver)
    monkeypatch.setattr(MODULE, "FileSystemEventHandler", DummyBase)

    with MODULE._WatchdogWatcher(["/watch/one", "/watch/two"]) as watcher:
        assert sorted(scheduled) == [
            ("/watch/one", True),
            ("/watch/two", True),
        ]
        observer = watcher._observer  # type: ignore[attr-defined]
        handler = observer.handler  # type: ignore[attr-defined]

        handler.on_created(SimpleNamespace(is_directory=False, src_path="/watch/two/file.jpg"))
        handler.on_moved(
            SimpleNamespace(
                is_directory=False,
                src_path="/watch/one/tmp.jpg",
                dest_path="/watch/one/file.jpg",
            )
        )
        handler.on_created(SimpleNamespace(is_directory=True, src_path="/watch/one/folder"))

        first = watcher._queue.get_nowait()
        second = watcher._queue.get_nowait()
        assert first == "/watch/two/file.jpg"
        assert second == "/watch/one/file.jpg"


def test_watchdog_watcher_requires_dependency(monkeypatch):
    monkeypatch.setattr(MODULE, "Observer", None)
    monkeypatch.setattr(MODULE, "FileSystemEventHandler", None)

    with pytest.raises(MODULE._WatchdogUnavailableError):
        MODULE._WatchdogWatcher(["/watch/me"])


def test_watch_mode_respects_rearm_delay(monkeypatch):
    calls: list[tuple[str, ...]] = []

    def fake_run_pipelines(args, sources):
        calls.append(tuple(sources))

    monkeypatch.setattr(MODULE, "_run_pipelines", fake_run_pipelines)

    events = [
        "/watch/one/file1.jpg",
        "/watch/one/file2.jpg",
        "/watch/two/file3.jpg",
    ]

    class DummyWatcher:
        def __init__(self, roots):
            assert tuple(roots) == ("/watch/one", "/watch/two")

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def __iter__(self):
            return iter(events)

    monkeypatch.setattr(MODULE, "_WatchdogWatcher", DummyWatcher)

    monotonic_values = iter([100.0, 101.0, 101.2, 101.3, 102.5, 102.7])
    monkeypatch.setattr(MODULE.time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(MODULE.time, "sleep", lambda _: None)

    args = SimpleNamespace(grace=0)
    MODULE._run_watch_mode(args, ["/watch/one", "/watch/two"])

    assert calls == [
        ("/watch/one", "/watch/two"),
        ("/watch/one",),
        ("/watch/two",),
    ]
