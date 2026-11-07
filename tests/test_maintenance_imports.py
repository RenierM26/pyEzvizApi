"""Compatibility exports must not eagerly require media or Home Assistant."""
import os
from pathlib import Path
import subprocess
import sys


def test_complete_export_surface_and_cli_parser_load_without_optional_runtimes(tmp_path):
    script = '''
import importlib.abc
import sys
class BlockOptional(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'av', 'homeassistant'}:
            raise AssertionError('unexpected optional runtime import: ' + fullname)
sys.meta_path.insert(0, BlockOptional())
import pyezvizapi
from pyezvizapi._cli_arguments import build_parser
for name in pyezvizapi.__all__:
    getattr(pyezvizapi, name)
assert build_parser().parse_args([]).action is None
assert not {'av', 'homeassistant'} & sys.modules.keys()
'''
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])},
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert result.returncode == 0, result.stderr
