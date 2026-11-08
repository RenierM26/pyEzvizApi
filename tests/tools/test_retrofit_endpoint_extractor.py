from __future__ import annotations

from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
import subprocess
import sys
from types import ModuleType

import pytest

from tests._paths import ROOT

SCRIPT = ROOT / "tools/apk-re/bin/extract-retrofit-endpoints"


def load_extractor() -> ModuleType:
    loader = SourceFileLoader("extract_retrofit_endpoints", str(SCRIPT))
    spec = spec_from_loader(loader.name, loader)
    assert spec is not None
    module = module_from_spec(spec)
    sys.modules[loader.name] = module
    loader.exec_module(module)
    return module


def test_known_paths_match_exact_and_composed_fragments(tmp_path: Path) -> None:
    extractor = load_extractor()
    api_endpoints = tmp_path / "api_endpoints.py"
    api_endpoints.write_text(
        "\n".join(
            [
                'API_ENDPOINT_DEVICES = "/v3/devices/"',
                'API_ENDPOINT_PTZCONTROL = "/ptzControl"',
                'API_ENDPOINT_VIDEO_ENCRYPT = "/encryptedInfo/risk"',
                'API_ENDPOINT_STREAMING_VTM = "/v3/streaming/vtm/{device_serial}/{channel_no}"',
            ]
        ),
        encoding="utf-8",
    )

    known_paths = extractor.load_known_paths(api_endpoints)

    assert extractor.is_implemented("/v3/streaming/vtm/{deviceSerial}/{channelNo}", known_paths)
    assert extractor.is_implemented("/v3/devices/{deviceSerial}/ptzControl", known_paths)
    assert not extractor.is_implemented("/v3/devices/{deviceSerial}/unknown", known_paths)


def test_known_paths_match_composed_python_endpoint_expressions(tmp_path: Path) -> None:
    extractor = load_extractor()
    api_endpoints = tmp_path / "api_endpoints.py"
    api_endpoints.write_text(
        "\n".join(
            [
                'API_ENDPOINT_DEVICES = "/v3/devices/"',
                'API_ENDPOINT_PTZCONTROL = "/ptzControl"',
                'API_ENDPOINT_VIDEO_ENCRYPT = "encryptedInfo/risk"',
            ]
        ),
        encoding="utf-8",
    )
    client = tmp_path / "client.py"
    client.write_text(
        "\n".join(
            [
                "def routes(serial):",
                '    literal = f"{API_ENDPOINT_DEVICES}{API_ENDPOINT_VIDEO_ENCRYPT}"',
                '    dynamic = f"{API_ENDPOINT_DEVICES}{serial}{API_ENDPOINT_PTZCONTROL}"',
            ]
        ),
        encoding="utf-8",
    )

    known_paths = extractor.load_known_paths(api_endpoints)

    assert extractor.is_implemented("/v3/devices/encryptedInfo/risk", known_paths)
    assert extractor.is_implemented("/v3/devices/{deviceSerial}/ptzControl", known_paths)
    assert not extractor.is_implemented("/v3/devices/ptzControl", known_paths)


def test_markdown_reports_composed_coverage(tmp_path: Path) -> None:
    extractor = load_extractor()
    api_endpoints = tmp_path / "api_endpoints.py"
    api_endpoints.write_text(
        "\n".join(
            [
                'API_ENDPOINT_DEVICES = "/v3/devices/"',
                'API_ENDPOINT_PTZCONTROL = "/ptzControl"',
            ]
        ),
        encoding="utf-8",
    )
    known_paths = extractor.load_known_paths(api_endpoints)
    endpoints = [
        extractor.Endpoint(
            source="DeviceApi.java",
            http_method="PUT",
            path="/v3/devices/{deviceSerial}/ptzControl",
            java_method="ptzControl",
            params=("Path:deviceSerial",),
        ),
        extractor.Endpoint(
            source="DeviceApi.java",
            http_method="GET",
            path="/v3/devices/{deviceSerial}/unknown",
            java_method="unknown",
            params=("Path:deviceSerial",),
        ),
    ]

    report = extractor.markdown(endpoints, known_paths)

    assert "- Paths detected in pyezvizapi: 1" in report
    assert "| yes | PUT | `/v3/devices/{deviceSerial}/ptzControl`" in report
    assert "| no | GET | `/v3/devices/{deviceSerial}/unknown`" in report


@pytest.mark.parametrize("entry", ["legacy", "canonical"])
def test_packaged_known_paths_find_nested_owner_expressions(tmp_path: Path, entry: str) -> None:
    extractor = load_extractor()
    package = tmp_path / "pyezvizapi"
    cloud = package / "cloud"
    operations = cloud / "operations"
    operations.mkdir(parents=True)
    legacy = package / "api_endpoints.py"
    legacy.write_text('raise RuntimeError("The inventory must not execute source files")\n')
    canonical = cloud / "endpoints.py"
    canonical.write_text('API_ENDPOINT_BASE = "/api"\n')
    (operations / "settings.py").write_text(
        'def route(serial, _owner):\n'
        '    return f"{_owner.API_ENDPOINT_BASE}/{serial}/settings"\n'
    )
    known = extractor.load_known_paths(legacy if entry == "legacy" else canonical)
    assert extractor.is_implemented("/api/{serial}/settings", known)
    assert not extractor.is_implemented("/api/{serial}/unknown", known)


def test_real_legacy_and_canonical_endpoint_inventories_match() -> None:
    extractor = load_extractor()
    legacy = extractor.load_known_paths(ROOT / "pyezvizapi/api_endpoints.py")
    canonical = extractor.load_known_paths(ROOT / "pyezvizapi/cloud/endpoints.py")
    assert legacy == canonical
    assert extractor.is_implemented("/v3/devices/{serial}/ptzControl", legacy)


def test_annotation_inventory_parses_java_signatures(tmp_path: Path) -> None:
    extractor = load_extractor()
    source = tmp_path / "DeviceApi.java"
    source.write_text(
        '@GET("/first")\n'
        'public abstract Observable<Map<String, List<Result[]>>> first(@Query("id") String id);\n'
        '@POST("/second")\n'
        'Single<Result[]> second(@Field("name") String value); // JADX source comment\n'
    )
    endpoints = extractor.extract_from_file(source, tmp_path)
    assert [(item.java_method, item.path, item.params) for item in endpoints] == [
        ("first", "/first", ("Query:id",)),
        ("second", "/second", ("Field:name",)),
    ]


def test_malformed_java_whitespace_finishes_without_backtracking(tmp_path: Path) -> None:
    source = tmp_path / "Malformed.java"
    source.write_text('@GET("/missing")\n' + ' ' * 50000 + '!\n')
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(tmp_path)],
        capture_output=True, text=True, timeout=3, check=True,
    )
    assert "Extracted endpoints: 0" in result.stdout
