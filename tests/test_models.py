from __future__ import annotations

from pyezvizapi.models import EzvizDeviceRecord, build_device_records_map


def test_device_record_from_api_tolerates_mixed_shapes() -> None:
    record = EzvizDeviceRecord.from_api(
        "ABC123",
        {
            "deviceInfos": {
                "name": "Front Door",
                "deviceCategory": "camera",
                "deviceSubCategory": "doorbell",
                "version": "1.2.3",
                "status": 1,
                "supportExt": {"SupportExt": "1"},
            },
            "STATUS": {"globalStatus": 0, "optionals": {"foo": "bar"}},
            "SWITCH": [
                {"type": 7, "enable": 1},
                {"type": 21, "enable": False},
                {"type": "ignored", "enable": True},
            ],
            "CONNECTION": {"localIp": "192.0.2.10"},
            "VTM": {"0": {"battery": 88}},
            "CLOUD": {"0": {"cloud": True}},
        },
    )

    assert record.serial == "ABC123"
    assert record.name == "Front Door"
    assert record.device_category == "camera"
    assert record.device_sub_category == "doorbell"
    assert record.status == 1
    assert record.switches == {7: True, 21: False}
    assert record.connection == {"localIp": "192.0.2.10"}
    assert record.vtm == {"battery": 88}
    assert record.cloud == {"cloud": True}


def test_build_device_records_map_wraps_payloads() -> None:
    records = build_device_records_map({"ABC123": {"deviceInfos": {"name": "Camera"}}})

    assert list(records) == ["ABC123"]
    assert records["ABC123"].name == "Camera"
