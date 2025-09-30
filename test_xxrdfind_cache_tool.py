import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("xxrdfind_cache_tool.py")
SPEC = importlib.util.spec_from_file_location("xxrdfind_cache_tool", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_dry_run_reports_all_cache_files(tmp_path):
    cache_root = tmp_path / "root"
    cache_root.mkdir()
    files = [
        cache_root / ".xxrdfind_cache.json",
        cache_root / ".xxrdfind_cache_stripped.json",
    ]
    for file in files:
        file.write_text("{}")

    removed = MODULE.remove_cache_files([str(cache_root)], dry_run=True)

    assert removed == len(files)
    for file in files:
        assert file.exists()


def test_recursive_removal(tmp_path):
    cache_root = tmp_path / "root"
    nested = cache_root / "nested"
    nested.mkdir(parents=True)
    files = [
        cache_root / ".xxrdfind_cache.json",
        nested / ".xxrdfind_cache.json",
        nested / ".xxrdfind_cache_stripped.json",
    ]
    for file in files:
        file.write_text("{}")

    removed = MODULE.remove_cache_files([str(cache_root)], recursive=True)

    assert removed == len(files)
    for file in files:
        assert not file.exists()
