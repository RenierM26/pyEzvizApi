from __future__ import annotations

import importlib.util

from pyezvizapi.__main__ import _format_cell, _write_table


def test_cli_imports_without_pandas_installed() -> None:
    assert importlib.util.find_spec("pandas") is None


def test_format_cell_handles_common_table_values() -> None:
    assert _format_cell(None) == ""
    assert _format_cell(True) == "True"
    assert _format_cell({"b": 2, "a": 1}) == '{"a": 1, "b": 2}'


def test_write_table_outputs_fixed_width_rows(capsys) -> None:
    _write_table(
        [
            {"serial": "ABC", "name": "Front", "online": True},
            {"serial": "XYZ", "name": None, "online": False},
        ],
        ["serial", "name", "online"],
    )

    output = capsys.readouterr().out
    assert "serial" in output
    assert "ABC" in output
    assert "Front" in output
    assert "XYZ" in output
    assert "False" in output
