"""Stored SD catalog and explicit-route batch CLI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.recordings import (
    RecordingCatalog,
    download_recordings,
    query_recordings,
    write_recording_json,
)


def add_recordings_arguments(subparsers: Any) -> None:
    parser = subparsers.add_parser("recordings", help="Query SD index and download a saved catalog")
    actions = parser.add_subparsers(dest="recordings_action", required=True)
    listing = actions.add_parser("list", help="Snapshot the cloud SD index (not a LAN query)")
    listing.add_argument("--serial", required=True)
    listing.add_argument("--channel", type=int, default=0)
    listing.add_argument("--begin-time", required=True, help="UTC YYYYMMDDTHHMMSSZ")
    listing.add_argument("--end-time", required=True, help="UTC YYYYMMDDTHHMMSSZ")
    listing.add_argument("--timezone", required=True, help="IANA index/native selector timezone")
    listing.add_argument("--page-size", type=int, default=100)
    listing.add_argument("--max-queries", type=int, default=256)
    listing.add_argument("--max-records", type=int, default=10000)
    listing.add_argument("--catalog", required=True, help="Output JSON snapshot")
    download = actions.add_parser(
        "download", help="Download all catalog intervals; hash-verified resume"
    )
    download.add_argument("--catalog", required=True)
    download.add_argument("--output", required=True, help="Output directory (one writer at a time)")
    download.add_argument(
        "--source", choices=("local-playback", "cloud-playback", "both"), required=True
    )
    download.add_argument("--local-channel", type=int, default=1)
    download.add_argument("--cloud-channel", type=int, help="Default: catalog channel")
    download.add_argument("--host", help="Explicit LAN camera IPv4 address")
    download.add_argument(
        "--lan-password-file", help="Private file containing current device password"
    )
    download.add_argument("--lan-username", default="admin")
    download.add_argument(
        "--media-key-file", help="Private cloud recording key file (otherwise account lookup)"
    )
    download.add_argument("--decrypt", action=argparse.BooleanOptionalAction, default=True)
    download.add_argument("--max-clips", type=int, default=10000)
    download.add_argument("--max-bytes", type=int, default=128 * 1024 * 1024, help="Per clip")
    download.add_argument("--transfer-timeout", type=float, default=60, help="Per clip seconds")


def handle_recordings(args: argparse.Namespace, client: Any) -> int:
    try:
        return _handle(args, client)
    except (OSError, ValueError, TypeError) as error:
        raise PyEzvizError(
            "Could not read/write recording catalog, manifest or credential file"
        ) from error


def _handle(args: argparse.Namespace, client: Any) -> int:
    if args.recordings_action == "list":
        catalog = query_recordings(
            client,
            args.serial,
            args.begin_time,
            args.end_time,
            channel=args.channel,
            timezone=args.timezone,
            page_size=args.page_size,
            max_queries=args.max_queries,
            max_records=args.max_records,
        )
        result = catalog.to_dict()
        write_recording_json(Path(args.catalog), result)
        print(json.dumps(result, indent=2))
        return 0
    catalog = RecordingCatalog.from_dict(json.loads(Path(args.catalog).read_text()))
    routes = ("local-playback", "cloud-playback") if args.source == "both" else (args.source,)
    password = (
        Path(args.lan_password_file).read_bytes().rstrip(b"\r\n")
        if args.lan_password_file
        else None
    )
    key = Path(args.media_key_file).read_text().rstrip("\r\n") if args.media_key_file else None
    if "local-playback" in routes and (not args.host or not password):
        raise PyEzvizError("LAN download requires --host and --lan-password-file")
    results = {}
    for route in routes:
        results[route] = download_recordings(
            client,
            catalog,
            args.output,
            source=route,
            channel=args.local_channel if route == "local-playback" else args.cloud_channel,
            host=args.host,
            password=password,
            username=args.lan_username,
            media_key=key,
            decrypt=args.decrypt,
            max_clips=args.max_clips,
            max_bytes=args.max_bytes,
            transfer_timeout=args.transfer_timeout,
        )
    print(json.dumps(results, indent=2))
    return 1 if any(report["failed"] for report in results.values()) else 0
