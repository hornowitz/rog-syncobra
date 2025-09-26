import importlib.util
import queue
import sys
import types
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("photoprism-watcher.py")
SPEC = importlib.util.spec_from_file_location("photoprism_watcher", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
if "requests" not in sys.modules:
    requests_stub = types.SimpleNamespace(Session=lambda: types.SimpleNamespace())
    sys.modules["requests"] = requests_stub

if "watchdog" not in sys.modules:
    watchdog_pkg = types.ModuleType("watchdog")
    watchdog_events = types.ModuleType("watchdog.events")
    watchdog_observers = types.ModuleType("watchdog.observers")

    class _FileSystemEventHandler:
        pass

    class _FileCreatedEvent:
        pass

    class _FileModifiedEvent:
        pass

    class _FileMovedEvent:
        pass

    class _Observer:
        def schedule(self, *args, **kwargs):  # pragma: no cover - stub only
            pass

        def start(self):  # pragma: no cover - stub only
            pass

        def stop(self):  # pragma: no cover - stub only
            pass

        def join(self, *args, **kwargs):  # pragma: no cover - stub only
            pass

    watchdog_events.FileCreatedEvent = _FileCreatedEvent
    watchdog_events.FileModifiedEvent = _FileModifiedEvent
    watchdog_events.FileMovedEvent = _FileMovedEvent
    watchdog_events.FileSystemEventHandler = _FileSystemEventHandler
    watchdog_observers.Observer = _Observer

    sys.modules["watchdog"] = watchdog_pkg
    sys.modules["watchdog.events"] = watchdog_events
    sys.modules["watchdog.observers"] = watchdog_observers
    watchdog_pkg.events = watchdog_events
    watchdog_pkg.observers = watchdog_observers
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules["photoprism_watcher"] = MODULE
SPEC.loader.exec_module(MODULE)

Config = MODULE.Config
MonthEventHandler = MODULE.MonthEventHandler
MonthQueue = MODULE.MonthQueue
_normalize_pp_base_url = MODULE._normalize_pp_base_url


class MonthEventHandlerTest(unittest.TestCase):
    def test_month_key_returns_year_month(self):
        cfg = Config(
            watch_dirs=("/root/watch",),
            dest_root="/dest",
            pp_base_url="http://example",
        )
        handler = MonthEventHandler(cfg, queue.Queue())

        self.assertEqual(
            handler._month_key("/root/watch/2025/08/example.jpg"),
            "2025/08",
        )

    def test_month_key_supports_multiple_roots(self):
        cfg = Config(
            watch_dirs=("/root/watch", "/mnt/photos"),
            dest_root="/dest",
            pp_base_url="http://example",
        )
        handler = MonthEventHandler(cfg, queue.Queue())

        self.assertEqual(
            handler._month_key("/mnt/photos/2023/12/img.png"),
            "2023/12",
        )


class HelpersTest(unittest.TestCase):
    def test_normalizes_base_url_without_api_suffix(self):
        cfg = Config(
            watch_dirs=("/root/watch",),
            dest_root="/dest",
            pp_base_url="http://photos.example.org",
        )
        self.assertEqual(cfg.pp_base_url, "http://photos.example.org/api/v1")

    def test_month_queue_put_returns_false_for_duplicates(self):
        q = MonthQueue()
        self.assertTrue(q.put("2024/01"))
        self.assertFalse(q.put("2024/01"))


class NormalizeFunctionTest(unittest.TestCase):
    def test_normalize_handles_existing_suffix(self):
        self.assertEqual(
            _normalize_pp_base_url("http://host/api/v1"),
            "http://host/api/v1",
        )

    def test_normalize_handles_custom_base_path(self):
        self.assertEqual(
            _normalize_pp_base_url("http://host/photos"),
            "http://host/photos/api/v1",
        )


if __name__ == "__main__":
    unittest.main()
