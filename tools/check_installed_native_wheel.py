"""Offline smoke check for a wheel installed into an isolated base environment.

Run with that environment's `python -I`; never starts a source or contacts HA.
"""
from importlib import metadata, util
import json
from pathlib import Path
import sys

import pyezvizapi
from pyezvizapi.native_stream import (
    NativeMpegTsStream,
    NativeSourceClock,
    NativeStreamOptions,
    NativeTrackSelection,
)


def main() -> None:
    package = Path(pyezvizapi.__file__).resolve()
    if not package.is_relative_to(Path(sys.prefix).resolve()):
        raise RuntimeError("Smoke check must import the installed wheel, not a checkout")
    if util.find_spec("av") is not None or util.find_spec("homeassistant") is not None:
        raise RuntimeError("Use an isolated base environment without PyAV or HA")

    def forbidden_source():
        raise RuntimeError("Packaging checks must never acquire a source")

    owner = NativeMpegTsStream(
        forbidden_source,
        NativeStreamOptions(NativeTrackSelection(480, 448), "h264"),
    )
    if owner.source_clock is not None:
        raise RuntimeError("An unopened owner must not invent a source clock")
    owner.close()
    if "av" in sys.modules or "homeassistant" in sys.modules:
        raise RuntimeError("Optional streaming/HA dependencies were imported eagerly")
    if not (package.parent / "py.typed").is_file():
        raise RuntimeError("Wheel lost its typing marker")
    print(json.dumps({
        "version": metadata.version("pyezvizapi"),
        "installed_package": str(package),
        "source_factory_called": False,
        "optional_dependencies_loaded": False,
        "source_clock_value": NativeSourceClock(90000).origin_90k,
        "owner_status": owner.receipt["status"],
    }, indent=2))


if __name__ == "__main__":
    main()
