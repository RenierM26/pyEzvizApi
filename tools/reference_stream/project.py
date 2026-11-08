"""Verified-build reference event projection. No native clock or missing pixels invented."""

from __future__ import annotations

import collections
import hashlib
from typing import Any


def require(condition: Any, message: str) -> None:
    if not condition:
        raise ValueError(message)


def key(n):
    return (
        n["sid"],
        n["raw"],
        n["frame"],
        n["secondary_sid"],
        n["secondary_raw"],
        n["secondary_frame"],
    )


def project(rows, cut):  # noqa: PLR0912, PLR0915 - preserve observed event ordering
    es = [e for e in rows if e.get("device_mono_ns", cut + 1) <= cut]
    by = collections.defaultdict(list)
    children = collections.defaultdict(list)
    for e in es:
        by[e.get("event")].append(e)
        if e.get("schedule") is not None:
            children[e["schedule"]].append(e)
    require(not by["error"], "native hook error")
    require(
        not by["drop_request"] and not by["copy_render"], "unsupported drop/copy-render observation"
    )
    origin = es[0]["device_mono_ns"]
    events: list[tuple[int, int, dict[str, Any]]] = []

    def add(e, kind, **fields):
        events.append(
            (
                e["device_mono_ns"],
                len(events),
                dict(kind=kind, at_ms=(e["device_mono_ns"] - origin) // 1000000, **fields),
            )
        )

    for e in by["decoded_picture"]:
        if e["payload_is_null"] and not e["payload_bytes"]:
            continue
        require(
            not e["payload_is_null"]
            and e["payload_bytes"] > 0
            and (e["codec"], e["tracks"]) == (133, 2),
            "unsupported decoded profile",
        )
        add(
            e,
            "lens_picture",
            id=f"offer:{e['call']}",
            lens=e["sid"] - 224,
            raw_time=e["raw"],
            media_ms=e["media_ms"],
            frame_number=e["frame"],
            native_header=e["header_words"],
        )
    admissions = by["video_queue_admitted"]
    ids = {key(e["copy"]["node"]): f"pair:{i}" for i, e in enumerate(admissions)}
    pictures = {e["copy"]["node"]["media_ms"]: f"pair:{i}" for i, e in enumerate(admissions)}
    require(
        len(ids) == len(admissions) and len(pictures) == len(admissions),
        "ambiguous admitted identity/media time",
    )
    queues = {e["queue"] for e in admissions}
    peek = {}
    for e in es:
        kind = e.get("event")
        if kind == "staging_return":
            add(e, "stage_push")
            if e["caller"] == "0x124af7":
                add(e, "video_unavailable", staging_result=e["result"])
        elif kind == "video_queue_admitted":
            require(e["result"] == 1, "queue admission failed")
            add(e, "render_admit", id=ids[key(e["copy"]["node"])])
        elif kind == "node_peek" and e["queue"] in queues and e["node"] is not None:
            peek[e["queue"]] = key(e["node"])
        elif kind == "node_commit" and e["queue"] in queues:
            add(e, "render_release", id=ids[peek[e["queue"]]])
    epoch = -1
    previous = None
    for e in by["schedule_enter"]:
        r = children[e["call"]]
        counts = [x for x in r if x["event"] == "node_count"]
        if not counts:
            continue
        require(
            (
                e["frame_speed"],
                e["smooth"],
                e["mode"],
                e["sync"],
                e["node_limit"],
                e["pending_rebase"],
            )
            == (1, 0, 0, 0, 6, 0),
            "unsupported scheduler profile",
        )
        if e["origin_ms"] != previous:
            epoch += 1
            previous = e["origin_ms"]
            add(counts[0], "video_epoch", epoch=epoch, origin_ms=previous)
        add(
            counts[0],
            "video_observed_tick",
            epoch=epoch,
            id=pictures[e["picture_ms"]],
            relative_ms=e["arg1"],
            elapsed_ms=e["elapsed_ms"],
            depth=counts[0]["data"],
            speed=e["speed"],
            bias_ms=e["bias"],
            interval_ms=e["frame_interval"],
        )
        if any(x["event"] == "display_request" for x in r) and len(counts) >= 2:
            rendered = [x for x in r if x["event"] == "render_callback"]
            require(len(rendered) == 1, "ambiguous render completion")
            add(
                counts[-1],
                "video_display_complete",
                id=ids[key(rendered[0]["node"])],
                depth=counts[-1]["data"],
            )
    events.sort(key=lambda e: e[:2])
    return [e[-1] for e in events]


def blob(root, row):
    path = root / row["file"]
    require(
        path.parent.resolve() == root.resolve() and not path.is_symlink(),
        "payload path outside capture",
    )
    require(
        type(row["offset"]) is int
        and row["offset"] >= 0
        and type(row["bytes"]) is int
        and 0 < row["bytes"] <= 12 * 1024 * 1024,
        "invalid payload extent",
    )
    with path.open("rb") as f:
        f.seek(row["offset"])
        b = f.read(row["bytes"])
    require(
        len(b) == row["bytes"] and hashlib.sha256(b).hexdigest() == row["sha256"],
        "payload fingerprint mismatch",
    )
    return b


def manifest(root, rows, r):
    k = (r["sid"], r["raw"], r["frame"])
    src = next(
        x
        for x in rows
        if x.get("event") == "native_pixels" and (x["sid"], x["raw"], x["frame"]) == k
    )
    u = next(
        x
        for x in rows
        if x.get("event") == "update"
        and x.get("cNative")
        and tuple(x["cNative"]["header"][f] for f in ("sid", "raw", "frame")) == k
    )
    end = next(
        x["device_mono_ns"]
        for x in rows
        if x.get("event") == "update_return" and x["id"] == u["id"]
    )
    uploads = [
        x
        for x in rows
        if x.get("event") == "plane_upload" and x["id"] == u["id"] and x["format"] == 5
    ]
    require(len(uploads) == 3, "incomplete renderer uploads")
    samplers = []
    for up in uploads:
        matches = [
            x
            for x in rows
            if x.get("event") == "sampler"
            and u["device_mono_ns"] < x["device_mono_ns"] < end
            and x["arg3"] == up["texture"]
        ]
        require(len(matches) == 1, "ambiguous renderer sampler")
        sm = matches[0]
        samplers.append(dict(name=sm["name"], unit=sm["arg2"], texture=sm["arg3"]))
    layout = dict(
        renderer_format=u["format"],
        width=u["width"],
        height=u["height"],
        sid=k[0],
        raw_timestamp=k[1],
        frame_index=k[2],
        payload_matches=u["cNative"]["payload_matches"],
        uploads=[
            {f: x[f] for f in ("width", "height", "format", "offset", "texture")} for x in uploads
        ],
        samplers=samplers,
    )
    return dict(
        id=f"native:{k[0]}:{k[1]}:{k[2]}",
        input_header=src["header_words"],
        render_header=r["header_words"],
        input_offset=0,
        render_offset=0,
        input_sha256=src["sha256"],
        render_sha256=r["sha256"],
        renderer_layout=layout,
    ), blob(root, src) + blob(root, r)
