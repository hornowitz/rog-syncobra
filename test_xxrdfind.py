import json
import sys
import tempfile
import types
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

if "xxhash" not in sys.modules:
    class _DummyHash:
        def update(self, _):
            pass

        def hexdigest(self):
            return "dummy"

    xxhash_stub = types.SimpleNamespace(xxh64=lambda: _DummyHash())
    sys.modules["xxhash"] = xxhash_stub

if "tqdm" not in sys.modules:
    tqdm_module = types.ModuleType("tqdm")

    class _DummyTqdm:
        def __init__(self, *_, **__):
            pass

        def update(self, *_args, **_kwargs):
            pass

        def close(self):
            pass

    def _tqdm(*_args, **_kwargs):
        return _DummyTqdm()

    tqdm_module.tqdm = _tqdm
    sys.modules["tqdm"] = tqdm_module

import xxrdfind


class FileHashTest(TestCase):
    def test_skips_exiftool_for_unsupported_video_when_stripping_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            video_path = Path(tmp) / "example.mkv"
            video_path.write_bytes(b"data")

            with patch("xxrdfind.subprocess.Popen") as popen_mock:
                with self.assertLogs("xxrdfind", level="INFO") as logs:
                    result = xxrdfind.file_hash(video_path, strip_metadata=True)

            self.assertEqual((video_path, None, 'unsupported_exiftool_extension'), result)
            popen_mock.assert_not_called()
            self.assertTrue(
                any("skipping raw dedupe for" in message for message in logs.output),
                logs.output,
            )


class CacheFailureTest(TestCase):
    def test_failed_hash_is_cached_and_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "video.mp4"
            target.write_bytes(b"data")
            other = root / "other.mp4"
            other.write_bytes(b"xxxx")

            def fake_file_hash(path, strip_metadata=False, algorithm='xxh64'):
                return path, None, 'exiftool failed'

            cache_path = root / ".xxrdfind_cache_stripped.json"

            with patch("xxrdfind.file_hash", side_effect=fake_file_hash):
                xxrdfind.find_duplicates(
                    [root],
                    strip_metadata=True,
                    show_progress=False,
                )

            cache_data = json.loads(cache_path.read_text())
            rel = str(target.relative_to(root))
            self.assertIn('xxh64_failed', cache_data[rel])
            self.assertEqual('exiftool failed', cache_data[rel]['xxh64_failed'])

            with patch("xxrdfind.file_hash", side_effect=fake_file_hash) as file_hash_mock:
                xxrdfind.find_duplicates(
                    [root],
                    strip_metadata=True,
                    show_progress=False,
                )
                self.assertTrue(
                    all(call.args[0] != target for call in file_hash_mock.mock_calls),
                    file_hash_mock.mock_calls,
                )
