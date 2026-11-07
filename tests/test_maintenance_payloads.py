"""Malformed device/envelope regression probes; no network calls."""
# ruff: noqa: SLF001 -- these tests exercise private API parsing boundaries.
import logging
import traceback
from unittest.mock import Mock

import pytest

from pyezvizapi.client import EzvizClient
from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.models import EzvizDeviceRecord, build_device_records_map


@pytest.mark.parametrize("value", [0, False])
def test_record_preserves_explicit_offline_status(value):
    record = EzvizDeviceRecord.from_api("TEST", {"deviceInfos": {"status": value}, "STATUS": {"globalStatus": 1}})
    assert record.status == value


@pytest.mark.parametrize("section", ["deviceInfos", "STATUS", "VTM", "CLOUD", "CONNECTION", "WIFI", "QOS"])
@pytest.mark.parametrize("value", [[1], "broken", 12])
def test_record_tolerates_malformed_sections(section, value):
    payload = {section: value, "SWITCH": [None, 1, {}, {"type": 1, "enable": 0}]}
    record = EzvizDeviceRecord.from_api("TEST", payload)
    assert record.raw is payload
    assert record.switches == {1: False}


@pytest.mark.parametrize("payload", [None, [1], 12, "broken"])
def test_bad_record_does_not_hide_other_devices(payload):
    records = build_device_records_map({"BAD": payload, "GOOD": {"deviceInfos": {"name": "Camera", "status": 0}}})
    assert records["BAD"].name is None
    assert records["GOOD"].name == "Camera"
    assert records["GOOD"].status == 0


@pytest.mark.parametrize("payload", [[], None, "value", 7])
def test_json_object_boundary_rejects_non_objects(payload):
    with pytest.raises(PyEzvizError, match="object"):
        EzvizClient._parse_json(Mock(json=Mock(return_value=payload)))


@pytest.mark.parametrize("meta", [[1], "broken", 12, True])
def test_bad_meta_has_no_modern_code(meta):
    assert EzvizClient._meta_code({"meta": meta}) is None
    assert EzvizClient._response_code({"meta": meta, "resultCode": "-1"}) == "-1"


def test_api_error_does_not_echo_credentials_or_unbounded_payload(caplog):
    client = EzvizClient()
    payload = {"meta": {"code": 500, "message": "SECRET_CANARY"}, "accessToken": "SECRET_CANARY", "nested": {"sessionId": "SECRET_CANARY"}, "blob": "x" * 10000}
    try:
        with caplog.at_level(logging.DEBUG), pytest.raises(PyEzvizError) as caught:
            client._ensure_ok(payload, "Request rejected")
        assert "SECRET_CANARY" not in str(caught.value) + caplog.text
        assert len(str(caught.value)) < 1024
        assert "500" in str(caught.value)
    finally:
        client.close_session()


@pytest.mark.parametrize("code", ["SECRET_CANARY", "²", "+-1", "--1", "++1", "9" * 10000, 10**1000, None, True, [1]])
def test_response_summary_bounds_untrusted_codes(code):
    summary = EzvizClient._response_summary({"resultCode": code})
    assert "SECRET_CANARY" not in summary
    assert len(summary) < 100


def test_json_decode_error_does_not_echo_raw_body():
    response = Mock(json=Mock(side_effect=ValueError("SECRET_CANARY")), text="SECRET_CANARY")
    with pytest.raises(PyEzvizError) as caught:
        EzvizClient._parse_json(response)
    assert "SECRET_CANARY" not in str(caught.value)


@pytest.mark.parametrize("code", ["++1", "--1", "+-1", "-+1", "+", "-"])
def test_response_summary_rejects_malformed_signed_codes(code):
    assert EzvizClient._response_summary({"resultCode": code}) == "response code=None, fields=1"


def test_json_decode_error_traceback_does_not_echo_parser_message():
    response = Mock(json=Mock(side_effect=ValueError("SECRET_CANARY")))
    with pytest.raises(PyEzvizError) as caught:
        EzvizClient._parse_json(response)
    assert "SECRET_CANARY" not in "".join(traceback.format_exception(caught.value))


@pytest.mark.parametrize(("code", "expected"), [("-1", -1), ("+200", 200), ("0", 0), (500, 500)])
def test_response_summary_preserves_valid_numeric_codes(code, expected):
    assert EzvizClient._response_summary({"resultCode": code}) == f"response code={expected}, fields=1"
def test_boolean_result_code_is_not_api_acceptance():
    assert EzvizClient._is_ok({"resultCode": False}) is False


@pytest.mark.parametrize("code", [{"accessToken": "SECRET_CANARY"}, ["SECRET_CANARY"], "SECRET_CANARY", "+-1", True])
def test_logging_codes_never_return_untrusted_payload_values(code):
    assert EzvizClient._response_code({"resultCode": code}) is None


def test_request_debug_summaries_are_bounded_and_omit_string_values():
    assert "SECRET_CANARY" not in EzvizClient._summarize_payload("SECRET_CANARY")
    assert len(EzvizClient._summarize_payload({str(n): "SECRET_CANARY" for n in range(1000)})) < 1024
