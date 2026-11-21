"""One-attempt auth HTTP ownership, redaction and total-deadline boundary."""

from collections.abc import Iterator
from contextlib import contextmanager
import time
from typing import Any

import requests

from pyezvizapi.cloud.budget import MAX_BOOTSTRAP_BODY_BYTES, budgeted_http_call
from pyezvizapi.cloud.deadline import bounded_request_timeout, request_deadline
from pyezvizapi.exceptions import HTTPError


@contextmanager
def auth_http_response(
    session: requests.Session,
    operation: str,
    *,
    timeout: float,
    label: str,
    max_body_bytes: int = MAX_BOOTSTRAP_BODY_BYTES,
    transport_errors_as_http: bool = False,
    **kwargs: Any,
) -> Iterator[requests.Response]:
    """Close every acquired response; never redirect, retry or initiate delivery.

    The total deadline includes acquisition, decoded body and consumer parsing.
    An enclosing operation deadline can additionally include lock/preflight time.
    Preserve discovery/code-request timeout and connection exception families;
    CAPTCHA keeps its existing SDK HTTPError transport contract. All messages
    and displayed tracebacks omit the request URL, response and original cause.
    """
    response: requests.Response | None = None
    with request_deadline(time.monotonic() + timeout):
        try:
            try:
                response = budgeted_http_call(
                    session,
                    operation,
                    max_body_bytes=max_body_bytes,
                    timeout=bounded_request_timeout(timeout),
                    allow_redirects=False,
                    **kwargs,
                )
                if not 200 <= response.status_code < 300:
                    raise HTTPError(f"{label} HTTP request failed")
                yield response
            except requests.Timeout:
                if transport_errors_as_http:
                    raise HTTPError(f"{label} request failed") from None
                raise requests.Timeout(f"{label} request timed out") from None
            except requests.ConnectionError:
                if transport_errors_as_http:
                    raise HTTPError(f"{label} request failed") from None
                raise requests.ConnectionError(f"{label} connection failed") from None
            except requests.RequestException:
                raise HTTPError(f"{label} request failed") from None
        finally:
            if response is not None:
                response.close()
