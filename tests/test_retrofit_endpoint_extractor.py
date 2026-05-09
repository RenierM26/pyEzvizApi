from __future__ import annotations

from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
import sys
from types import ModuleType

SCRIPT = Path(__file__).resolve().parents[1] / "tools/apk-re/bin/extract-retrofit-endpoints"


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
                'API_ENDPOINT_STREAMING_VTM = "/v3/streaming/vtm/{device_serial}/{channel_no}"',
            ]
        ),
        encoding="utf-8",
    )

    known_paths = extractor.load_known_paths(api_endpoints)

    assert extractor.is_implemented("/v3/streaming/vtm/{deviceSerial}/{channelNo}", known_paths)
    assert extractor.is_implemented("/v3/devices/{deviceSerial}/ptzControl", known_paths)
    assert not extractor.is_implemented("/v3/devices/{deviceSerial}/unknown", known_paths)


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
