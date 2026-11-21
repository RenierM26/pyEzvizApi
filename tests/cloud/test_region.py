"""Test area resolution at the HTTP boundary without cloud access."""

import json

import pytest
import requests

from pyezvizapi.cloud.region import list_login_areas, resolve_login_host
from pyezvizapi.exceptions import PyEzvizError


@pytest.fixture
def lookup(monkeypatch):
    calls = []

    def configure(payload, status=200):
        def send(_session, request, **kwargs):
            calls.append(request)
            assert kwargs["allow_redirects"] is False
            assert kwargs["stream"] is True
            response = requests.Response()
            response.status_code = status
            response._content = (  # noqa: SLF001  # noqa: SLF001
                payload if isinstance(payload, bytes) else json.dumps(payload).encode()
            )
            response.__dict__["_content_consumed"] = True
            response.headers["Location"] = "https://other.example.test/"
            return response

        monkeypatch.setattr(requests.Session, "send", send)
        return calls

    return configure


@pytest.mark.parametrize("domain", ["apiius.ezvizlife.com", "https://APIIUS.ezvizlife.com/"])
def test_explicit_area_lookup_is_credential_free(lookup, domain):
    calls = lookup({"resultCode": "0", "areaDomain": domain, "httpDomain": "ignored"})
    assert resolve_login_host(314) == "apiius.ezvizlife.com"
    (request,) = calls
    assert request.url == "https://api.ezvizlife.com/api/area/domain"
    assert request.body == "areaId=314"
    assert not {"authorization", "cookie", "sessionid", "featurecode"} & {
        key.lower() for key in request.headers
    }


@pytest.mark.parametrize("area_id", [False, "314", 0, -1, 2**31])
def test_invalid_id_never_reaches_transport(lookup, area_id):
    calls = lookup({})
    with pytest.raises(ValueError, match="area ID"):
        resolve_login_host(area_id)
    assert calls == []


@pytest.mark.parametrize(
    ("status", "payload"),
    [
        (302, {}),
        (200, b"not json"),
        (200, b"x" * 16_385),
        (200, {"resultCode": "1", "areaDomain": "apiius.ezvizlife.com"}),
        (200, {"resultCode": "0", "domain": "apiius.ezvizlife.com"}),
        (200, {"resultCode": "0", "areaDomain": "apiius.ezvizlife.com.other.example"}),
        (200, {"resultCode": "0", "areaDomain": "https://apiius.ezvizlife.com/private"}),
        (200, {"resultCode": "0", "areaDomain": "https://user@apiius.ezvizlife.com"}),
    ],
)
def test_lookup_rejects_bad_responses_without_following_redirects(lookup, status, payload):
    calls = lookup(payload, status)
    with pytest.raises(PyEzvizError):
        resolve_login_host(314)
    assert len(calls) == 1


def test_catalog_supports_selection_by_name_without_network(lookup):
    calls = lookup({"resultCode": "0", "areaDomain": "apiieu.ezvizlife.com"})
    areas = list_login_areas()
    assert len(areas) > 200
    assert len({area.area_id for area in areas}) == len(areas)
    assert list(areas) == sorted(areas, key=lambda area: (area.name.casefold(), area.area_id))
    area = next(area for area in areas if area.name == "South Africa")
    assert area.area_id == 437
    assert calls == []
    assert resolve_login_host(area.area_id) == "apiieu.ezvizlife.com"
    assert calls[0].body == "areaId=437"


def test_russia_matches_app_special_route_without_lookup(lookup):
    calls = lookup({})
    russia = next(area for area in list_login_areas() if area.name == "Russia")
    assert resolve_login_host(russia.area_id) == "api.ezvizru.com"
    assert calls == []
