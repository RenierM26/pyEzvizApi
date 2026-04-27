"""Validate RTSP credentials with Basic then Digest authentication."""

from __future__ import annotations

import argparse

from pyezvizapi.test_cam_rtsp import TestRTSPAuth


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="Camera IP address or hostname")
    parser.add_argument("username", help="RTSP username")
    parser.add_argument("password", help="RTSP password")
    parser.add_argument(
        "--uri",
        default="/Streaming/Channels/101",
        help="RTSP URI path to test (default: /Streaming/Channels/101)",
    )
    args = parser.parse_args()

    TestRTSPAuth(args.host, args.username, args.password, args.uri).main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
