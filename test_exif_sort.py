import importlib.util
import json
import sys
import types
from collections import deque
from datetime import datetime
from pathlib import Path

import pytest

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


def test_scan_media_extensions_detects_screenshot_name(tmp_path):
    (tmp_path / "Screenshot_20180221-143405.png").write_bytes(b"")

    result = MODULE.scan_media_extensions(
        str(tmp_path), recursive=False, extensions=MODULE.MEDIA_SCAN_EXTS
    )

    assert result.extensions == {".png"}
    assert result.screenshot_present is True


def test_scan_media_extensions_detects_prefixed_screenshot_name(tmp_path):
    (tmp_path / " Vacation_Screenshot_20180625-213104.png").write_bytes(b"")

    result = MODULE.scan_media_extensions(
        str(tmp_path), recursive=False, extensions=MODULE.MEDIA_SCAN_EXTS
    )

    assert result.extensions == {".png"}
    assert result.screenshot_present is True


def test_scan_media_extensions_extracts_timestamp(tmp_path):
    (tmp_path / "Screenshot_20180221-143405.png").write_bytes(b"")

    result = MODULE.scan_media_extensions(
        str(tmp_path), recursive=False, extensions=MODULE.MEDIA_SCAN_EXTS
    )

    expected = {"Screenshot_20180221-143405.png": datetime(2018, 2, 21, 14, 34, 5)}
    assert result.screenshot_timestamps == expected


def test_scan_media_extensions_extracts_localised_timestamp(tmp_path):
    (tmp_path / "Bildschirmfoto 2021-04-05 um 07.08.09.png").write_bytes(b"")
    (tmp_path / "Screen Shot 2022-05-06 at 09.10.11 PM.png").write_bytes(b"")

    result = MODULE.scan_media_extensions(
        str(tmp_path), recursive=False, extensions=MODULE.MEDIA_SCAN_EXTS
    )

    assert result.screenshot_present is True
    timestamps = result.screenshot_timestamps
    assert timestamps["Bildschirmfoto 2021-04-05 um 07.08.09.png"] == datetime(
        2021, 4, 5, 7, 8, 9
    )
    assert timestamps["Screen Shot 2022-05-06 at 09.10.11 PM.png"] == datetime(
        2022, 5, 6, 21, 10, 11
    )


def test_scan_media_extensions_detects_screenshot_without_digits(tmp_path):
    (tmp_path / "Vacation Screenshot.png").write_bytes(b"")

    result = MODULE.scan_media_extensions(
        str(tmp_path), recursive=False, extensions=MODULE.MEDIA_SCAN_EXTS
    )

    assert result.extensions == {".png"}
    assert result.screenshot_present is True


def test_scan_media_extensions_ignores_plain_png(tmp_path):
    (tmp_path / "holiday.png").write_bytes(b"")

    result = MODULE.scan_media_extensions(
        str(tmp_path), recursive=False, extensions=MODULE.MEDIA_SCAN_EXTS
    )

    assert result.extensions == {".png"}
    assert result.screenshot_present is False


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
            self._closed = False
            self._killed = False

        def communicate(self):
            self._closed = True
            return ("", "")

        def poll(self):
            return 0 if self._closed else None

        def kill(self):
            self._killed = True
            self._closed = True

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


def _extract_stay_open_payloads(instances):
    payloads = []
    for proc in instances:
        stdin = getattr(proc, "stdin", None)
        if stdin is None:
            continue
        for write in getattr(stdin, "writes", []):
            if "-echo3\n" not in write:
                continue
            before_marker, *_ = write.split("\n-echo3\n", 1)
            payloads.append(before_marker.split("\n"))
    return payloads


def test_exif_sort_sets_screenshot_timestamp_from_filename(monkeypatch, tmp_path):
    instances = []

    class DummyStdout:
        def __init__(self):
            self.lines = deque()

        def push_ready(self):
            self.lines.append("{ready}\n")

        def readline(self):
            if not self.lines:
                raise AssertionError("No output queued for exiftool mock")
            return self.lines.popleft()

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

        def poll(self):
            return None

        def kill(self):
            return None

        def communicate(self, *_args, **_kwargs):
            return ("", "")

    def fake_popen(*args, **kwargs):
        proc = DummyProc(*args, **kwargs)
        instances.append(proc)
        return proc

    monkeypatch.setattr(MODULE.subprocess, "Popen", fake_popen)

    (tmp_path / "Screenshot_20180221-143405.png").write_bytes(b"")

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

    payloads = _extract_stay_open_payloads(instances)
    timestamp_payloads = [
        payload
        for payload in payloads
        if "Screenshot_20180221-143405.png" in payload
        and any(part.startswith('-DateTimeOriginal=') for part in payload)
    ]
    assert timestamp_payloads, "Expected timestamp override command for screenshot"
    timestamp_parts = {
        part
        for payload in timestamp_payloads
        for part in payload
        if part.startswith('-DateTimeOriginal=')
    }
    assert '-DateTimeOriginal=2018:02:21 14:34:05' in timestamp_parts


def test_exif_sort_uses_google_takeout_sidecar(monkeypatch, tmp_path):
    instances = []

    class DummyStdout:
        def __init__(self):
            self.lines = deque()

        def push_ready(self):
            self.lines.append("{ready}\n")

        def readline(self):
            if not self.lines:
                raise AssertionError("No output queued for exiftool mock")
            return self.lines.popleft()

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

        def poll(self):
            return None

        def kill(self):
            return None

        def communicate(self, *_args, **_kwargs):
            return ("", "")

    def fake_popen(*args, **kwargs):
        proc = DummyProc(*args, **kwargs)
        instances.append(proc)
        return proc

    monkeypatch.setattr(MODULE.subprocess, "Popen", fake_popen)

    (tmp_path / "IMG_8887.JPG").write_bytes(b"")
    metadata = {
        "title": "IMG_8887.JPG",
        "photoTakenTime": {
            "timestamp": "1506859200",
            "formatted": "2017-10-01 12:00:00 UTC",
        },
    }
    (tmp_path / "IMG_8887.json").write_text(json.dumps(metadata))

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

    payloads = _extract_stay_open_payloads(instances)
    timestamp_payloads = [
        payload
        for payload in payloads
        if "IMG_8887.JPG" in payload
        and any(part.startswith('-DateTimeOriginal=') for part in payload)
    ]
    assert timestamp_payloads, "Expected Google Takeout timestamp command"
    timestamp_parts = {
        part
        for payload in timestamp_payloads
        for part in payload
        if part.startswith('-DateTimeOriginal=')
    }
    assert '-DateTimeOriginal=2017:10:01 12:00:00' in timestamp_parts


def test_exif_sort_screenshot_rename_handles_missing_keywords(monkeypatch, tmp_path):
    instances = []

    class DummyStdout:
        def __init__(self):
            self.lines = deque()

        def push_ready(self):
            self.lines.append("{ready}\n")

        def readline(self):
            if not self.lines:
                raise AssertionError("No output queued for exiftool mock")
            return self.lines.popleft()

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

        def poll(self):
            return None

        def kill(self):
            return None

        def communicate(self, *_args, **_kwargs):
            return ("", "")

    def fake_popen(*args, **kwargs):
        proc = DummyProc(*args, **kwargs)
        instances.append(proc)
        return proc

    monkeypatch.setattr(MODULE.subprocess, "Popen", fake_popen)

    (tmp_path / "Screenshot_20180221-143405.png").write_bytes(b"")

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

    payloads = _extract_stay_open_payloads(instances)
    rename_tag = MODULE.PRIMARY_TIMESTAMP_TAG
    rename_payloads = [
        payload
        for payload in payloads
        if any(
            part.startswith(f'-Filename<{rename_tag}') and 'Screenshot%-c.%e' in part
            for part in payload
        )
    ]
    assert rename_payloads, "Expected screenshot rename command"
    for payload in rename_payloads:
        assert any('defined $Keywords and $Keywords=~/screenshot/i' in part for part in payload)
        assert any('screenshot|screen[ _-]?shot|bildschirmfoto' in part for part in payload)

    directory_payloads = [
        payload
        for payload in payloads
        if any(
            part.startswith(f'-Directory<{rename_tag}/Screenshots')
            for part in payload
        )
    ]
    assert directory_payloads, "Expected screenshot directory command"
    for payload in directory_payloads:
        assert any('defined $Keywords and $Keywords=~/screenshot/i' in part for part in payload)
        assert any('screenshot|screen[ _-]?shot|bildschirmfoto' in part for part in payload)


def test_exif_sort_whatsapp_handles_baseline_jpg(monkeypatch, tmp_path):
    instances = []

    class DummyStdout:
        def __init__(self):
            self.lines = deque()

        def push_ready(self):
            self.lines.append("{ready}\n")

        def readline(self):
            if not self.lines:
                raise AssertionError("No output queued for exiftool mock")
            return self.lines.popleft()

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

        def poll(self):
            return None

        def kill(self):
            return None

        def communicate(self, *_args, **_kwargs):
            return ("", "")

    def fake_popen(*args, **kwargs):
        proc = DummyProc(*args, **kwargs)
        instances.append(proc)
        return proc

    def fake_scan_media_extensions(*_args, **_kwargs):
        return MODULE.MediaScanResult(extensions={".jpg"})

    monkeypatch.setattr(MODULE.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(MODULE, "scan_media_extensions", fake_scan_media_extensions)

    (tmp_path / "IMG_8128.JPG").write_bytes(b"")

    args = types.SimpleNamespace(
        debug=False,
        year_month_sort=False,
        skip_marker=None,
        recursive=False,
        whatsapp=True,
        dry_run=False,
    )

    result = MODULE.exif_sort(str(tmp_path), str(tmp_path), args)
    assert result is True

    payloads = _extract_stay_open_payloads(instances)
    clauses = [
        payload[idx + 1]
        for payload in payloads
        for idx in range(len(payload) - 1)
        if payload[idx] == '-if'
    ]
    assert MODULE.WHATSAPP_IMAGE_IF_CLAUSE in clauses
    assert "^IMG_\\d{4,}\\.\\w*" in MODULE.WHATSAPP_IMAGE_IF_CLAUSE
    assert "$ImageWidth<=1600" in MODULE.WHATSAPP_IMAGE_IF_CLAUSE
    assert "$ImageHeight<=1600" in MODULE.WHATSAPP_IMAGE_IF_CLAUSE
    assert (
        "$jfifversion=~/1\\.01/i and $ImageWidth<=1600 and $ImageHeight<=1600"
        in MODULE.WHATSAPP_IMAGE_IF_CLAUSE
    )

    whatsapp_payloads = [
        payload
        for payload in payloads
        if MODULE.WHATSAPP_IMAGE_IF_CLAUSE in payload
    ]
    assert whatsapp_payloads, "Expected WhatsApp-specific exiftool commands"

    whatsapp_timestamp_updates: dict[str, list[str]] = {
        'CreateDate': [],
        'ModifyDate': [],
        'DateTimeOriginal': [],
    }
    for payload in whatsapp_payloads:
        for part in payload:
            for tag in whatsapp_timestamp_updates:
                prefix = f'-{tag}<'
                if part.startswith(prefix):
                    whatsapp_timestamp_updates[tag].append(part)
    for tag, updates in whatsapp_timestamp_updates.items():
        assert updates, f"Expected at least one update for {tag}"
        for update in updates:
            assert '${FileModifyDate' in update


def test_exif_sort_whatsapp_renames_prefer_file_modify(monkeypatch, tmp_path):
    instances = []

    class DummyStdout:
        def __init__(self):
            self.lines = deque()

        def push_ready(self):
            self.lines.append("{ready}\n")

        def readline(self):
            if not self.lines:
                raise AssertionError("No output queued for exiftool mock")
            return self.lines.popleft()

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

        def communicate(self, *args, **kwargs):
            return ("", "")

        def poll(self):
            return None

        def kill(self):
            return None

    def fake_popen(*args, **kwargs):
        proc = DummyProc(*args, **kwargs)
        instances.append(proc)
        return proc

    def fake_scan_media_extensions(*_args, **_kwargs):
        return MODULE.MediaScanResult(extensions={".jpg", ".mp4"})

    monkeypatch.setattr(MODULE.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(MODULE, "scan_media_extensions", fake_scan_media_extensions)

    (tmp_path / "IMG-20240101-WA0001.jpg").write_bytes(b"")

    args = types.SimpleNamespace(
        debug=False,
        year_month_sort=False,
        skip_marker=None,
        recursive=False,
        whatsapp=True,
        dry_run=False,
    )

    result = MODULE.exif_sort(str(tmp_path), str(tmp_path), args)
    assert result is True

    payloads = _extract_stay_open_payloads(instances)
    timestamp_tag = MODULE.WHATSAPP_TIMESTAMP_TAG

    file_cmds = [
        part
        for payload in payloads
        for part in payload
        if part.startswith('-FileName<') and 'WhatsApp%-c.%e' in part
    ]
    dir_cmds = [
        part
        for payload in payloads
        for part in payload
        if part.startswith('-Directory<') and '/WhatsApp' in part
    ]

    assert file_cmds, "Expected WhatsApp file rename commands"
    assert dir_cmds, "Expected WhatsApp directory commands"

    for cmd in file_cmds:
        assert cmd.startswith(f'-FileName<{timestamp_tag} ')
    for cmd in dir_cmds:
        assert cmd.startswith(f'-Directory<{timestamp_tag}/')


def test_exif_sort_guards_creation_date_commands(monkeypatch, tmp_path):
    instances = []

    def fake_scan_media_extensions(*_args, **_kwargs):
        return MODULE.MediaScanResult(extensions={".jpg"})

    monkeypatch.setattr(MODULE, "scan_media_extensions", fake_scan_media_extensions)
    monkeypatch.setattr(MODULE, "SCREENSHOT_EXTS", {".png"})

    class DummyStdout:
        def __init__(self):
            self.lines = deque()

        def push_ready(self):
            self.lines.append("{ready}\n")

        def readline(self):
            if not self.lines:
                raise AssertionError("No output queued for exiftool mock")
            return self.lines.popleft()

    class DummyStdin:
        def __init__(self, stdout):
            self.stdout = stdout
            self.writes = []

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

        def communicate(self, *args, **kwargs):
            return ("", "")

        def poll(self):
            return None

        def kill(self):
            return None

    def fake_popen(*args, **kwargs):
        proc = DummyProc(*args, **kwargs)
        instances.append(proc)
        return proc

    monkeypatch.setattr(MODULE.subprocess, "Popen", fake_popen)

    (tmp_path / "sample.JPG").write_bytes(b"")
    args = types.SimpleNamespace(
        debug=False,
        year_month_sort=False,
        skip_marker=None,
        recursive=False,
        whatsapp=False,
        dry_run=False,
        min_age_days=0,
    )

    result = MODULE.exif_sort(str(tmp_path), str(tmp_path), args)
    assert result is True

    payloads = _extract_stay_open_payloads(instances)
    timestamp_tag = MODULE.PRIMARY_TIMESTAMP_TAG
    timestamp_condition = MODULE.PRIMARY_TIMESTAMP_CONDITION
    dcim_payloads = [
        payload
        for payload in payloads
        if f'-Filename<{timestamp_tag}%-c.%e' in payload
    ]
    assert dcim_payloads, "DCIM rename commands were not queued"
    for payload in dcim_payloads:
        assert any(timestamp_condition in part for part in payload)
        extensions = [
            payload[idx + 1]
            for idx in range(len(payload) - 1)
            if payload[idx] in ('-ext', '-ext+')
        ]
        assert 'JPG' in extensions, payload
        assert any('not defined $Model or $Model eq ""' in part for part in payload), payload
        guard = (
            'not ('
            ' (defined $Keywords and $Keywords=~/whatsapp/i)'
            ' or (defined $Keys:Keywords and $Keys:Keywords=~/whatsapp/i)'
            ' or (defined $XMP:Subject and $XMP:Subject=~/whatsapp/i)'
            ')'
        )
        assert any(guard in part for part in payload), payload

    model_payloads = [
        payload for payload in payloads if any('${Model}' in part for part in payload)
    ]
    assert model_payloads, 'Camera model rename command missing'
    for payload in model_payloads:
        assert any('defined $Model' in part for part in payload), payload
        assert any('${Model}%-c.%e' in part for part in payload), payload

    # Ensure that creation-date based renames are gated by a defined check

    creation_payloads = [payload for payload in payloads if any("${CreationDate" in part for part in payload)]
    assert creation_payloads, "Creation-date rename commands were not queued"
    for payload in creation_payloads:
        assert any('defined $CreationDate' in part for part in payload), payload
        assert any('QuickTime:CreationDate' in part for part in payload), payload
        assert any(
            part.startswith('-Filename<${CreationDate;QuickTime:CreationDate;QuickTime:CreateDate}')
            for part in payload
        ), payload

    subsec_payloads = [
        payload
        for payload in payloads
        if any(f"{timestamp_tag}_$SubSecTimeOriginal" in part for part in payload)
    ]
    assert subsec_payloads, "Sub-second rename command missing"

@pytest.mark.parametrize(
    "warning_message",
    [
        "Warning: Unrecognized option -echo3\n",
        "Warning: Option -echo3 is not supported\n",
    ],
)
def test_exif_sort_falls_back_when_echo3_missing(monkeypatch, tmp_path, warning_message):
    stay_open_instances = []
    oneshot_commands = []

    class StayOpenStdout:
        def __init__(self, message: str):
            self.lines = deque([message])

        def readline(self):
            if self.lines:
                return self.lines.popleft()
            return ''

    class StayOpenStdin:
        def __init__(self):
            self.writes = []

        def write(self, data):
            self.writes.append(data)
            return len(data)

        def flush(self):
            return None

    class StayOpenProc:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs
            self.stdin = StayOpenStdin()
            self.stdout = StayOpenStdout(warning_message)
            self._killed = False
            self._terminated = False

        def poll(self):
            return None if not self._terminated else 0

        def kill(self):
            self._killed = True
            self._terminated = True

        def communicate(self):
            self._terminated = True
            return ("", "")

    class OneShotStdout:
        def __init__(self):
            self.lines = deque(["1 image files updated\n", "{ready}\n"])

        def readline(self):
            if self.lines:
                return self.lines.popleft()
            return ''

    class OneShotProc:
        def __init__(self, cmd, *args, **kwargs):
            self.cmd = cmd
            self.stdout = OneShotStdout()

        def wait(self):
            return 0

    def fake_popen(cmd, *args, **kwargs):
        if cmd[:3] == ['exiftool', '-stay_open', 'True']:
            proc = StayOpenProc(cmd, *args, **kwargs)
            stay_open_instances.append(proc)
            return proc
        oneshot_commands.append(cmd)
        proc = OneShotProc(cmd, *args, **kwargs)
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
    assert stay_open_instances, "stay-open exiftool should be attempted first"
    stay_open_proc = stay_open_instances[0]
    assert stay_open_proc._killed is True
    assert oneshot_commands, "fallback exiftool commands were not executed"
    first_cmd = oneshot_commands[0]
    assert first_cmd[0] == 'exiftool'
    assert '-q' in first_cmd
