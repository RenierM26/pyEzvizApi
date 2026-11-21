"""Test maintenance observations without contacting a device."""

import pytest

from pyezvizapi.devices.maintenance import firmware_upgrade_outcome, reboot_recovery_observed


@pytest.mark.parametrize(
    ("samples", "expected"),
    [
        ([True, None, True], False),
        ([True, False, None], False),
        ([True, False, None, True], True),
        ([True, True], False),
    ],
)
def test_reboot_recovery(samples: list[bool | None], expected: bool) -> None:
    assert reboot_recovery_observed(samples) is expected


@pytest.mark.parametrize(
    ("code", "version", "baseline", "expected"),
    [
        (1, "V2", "V1", "pending"),
        (3, "V2", "V1", "failed"),
        ("2", "V2", "V1", "complete"),
        (2, "V2", "V2", "unknown"),
        (2, "V1", "V1", "unknown"),
        (17, "V2", "V1", "unknown"),
        (None, "V2", "V1", "unknown"),
    ],
)
def test_upgrade_outcome(
    code: int | str | None, version: str, baseline: str, expected: str
) -> None:
    data = {"deviceInfos": {"version": version}, "STATUS": {"upgradeStatus": code}}
    assert (
        firmware_upgrade_outcome(data, target_version="V2", previous_version=baseline) == expected
    )
