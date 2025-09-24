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

            self.assertEqual((video_path, None), result)
            popen_mock.assert_not_called()
            self.assertTrue(
                any("skipping raw dedupe for" in message for message in logs.output),
                logs.output,
            )
