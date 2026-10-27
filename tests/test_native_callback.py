"""A native backend retry must not replace or print the original source error."""
import traceback

import pytest

from pyezvizapi import native_stream
from pyezvizapi.exceptions import PyEzvizError


def test_callback_failure_is_sticky_sanitized_and_does_not_pull_again():
    error = ValueError("private endpoint and credential detail")

    class Source:
        calls = 0
        closed = False

        def close(self):
            self.closed = True

        def iter_media_packets(self):
            return self

        def __iter__(self):
            return self

        def __next__(self):
            self.calls += 1
            raise error

    source = Source()
    reader = native_stream._PsInput(  # noqa: SLF001 - exercise the C callback contract.
        source, media_key=None, nalu_header_size=2,
        finite_source=False, check_stop=lambda: None,
    )
    try:
        for _attempt in range(3):
            with pytest.raises(PyEzvizError) as caught:
                reader.read(65536)
            assert "private endpoint" not in "".join(traceback.format_exception(caught.value))
            assert reader.failure is error
        assert source.calls == 1
    finally:
        reader.close()
    assert source.closed
