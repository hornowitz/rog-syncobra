import importlib.util
import sys
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("photoprism_api.py")
SPEC = importlib.util.spec_from_file_location("photoprism_api", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

_strip_photoprism_prefixes = MODULE._strip_photoprism_prefixes


def test_strip_prefix_preserves_leading_slash():
    result = _strip_photoprism_prefixes("/srv/photos/2024/01", ["/srv/photos"])
    assert result == "/2024/01"


def test_strip_prefix_handles_windows_backslashes():
    result = _strip_photoprism_prefixes("C:/Photos/2024/01", [r"C:\Photos"])
    assert result == "2024/01"


def test_strip_prefix_returns_original_when_unmatched():
    path = "2024/01"
    assert _strip_photoprism_prefixes(path, ["/unrelated"]) == path


def test_strip_prefix_empty_result_maps_to_root():
    assert _strip_photoprism_prefixes("C:/Photos", ["C:/Photos"]) == ""
