"""Non-acquiring receive-codec preflight; the provider still validates full SDP."""
from __future__ import annotations

_DIRECTIONS = {"sendrecv", "recvonly", "sendonly", "inactive"}


def _session_bundle_mids(lines: list[str]) -> set[str]:
    """Ignore media-level group lookalikes when recognizing bundle-only sections."""
    mids: set[str] = set()
    for raw in lines:
        line = raw.strip()
        if line.startswith("m="):
            break
        if line.startswith("a=group:"):
            fields = line[len("a=group:"):].split()
            if fields and fields[0] == "BUNDLE":
                mids.update(fields[1:])
    return mids


def receives_codec(offer: str, kind: str, codec: str, rate: int) -> bool:
    """Require a listed codec in a non-rejected media section that can receive."""
    lines = offer.splitlines()
    bundle_mids = _session_bundle_mids(lines)
    session_direction = "sendrecv"
    direction = session_direction
    payloads: set[str] = set()
    active = matched = bundle_only = False
    in_media = False
    mid = port = ""
    for raw in (*lines, "m="):
        line = raw.strip()
        if line.startswith("m="):
            # RFC 8843: a zero-port bundle-only member requests bundled transport,
            # not rejection. Full transport/SDP validity remains with the provider.
            accepted = port != "0" or (bundle_only and mid in bundle_mids)
            if active and matched and accepted and direction in {"recvonly", "sendrecv"}:
                return True
            fields = line[2:].split()
            in_media = True
            port = (fields[1].split("/", 1)[0].lstrip("0") or "0") if len(fields) > 1 else ""
            active = (len(fields) >= 4 and fields[0] == kind
                      and 0 < len(port) <= 5 and port.isascii() and port.isdecimal()
                      and int(port) <= 65535
                      and "RTP" in fields[2].split("/"))
            payloads = set(fields[3:]) if active else set()
            direction, matched = session_direction, False
            mid, bundle_only = "", False
        elif line.startswith("a=") and line[2:] in _DIRECTIONS:
            direction = line[2:]
            if not in_media:
                session_direction = direction
        elif in_media and line == "a=bundle-only":
            bundle_only = True
        elif in_media and line.startswith("a=mid:"):
            values = line[len("a=mid:"):].split()
            mid = values[0] if len(values) == 1 else ""
        elif active and line.startswith("a=rtpmap:"):
            mapping = line[len("a=rtpmap:"):].split()
            if len(mapping) == 2 and mapping[0] in payloads:
                encoding = mapping[1].split("/")
                if (len(encoding) >= 2 and encoding[0].casefold() == codec.casefold()
                        and encoding[1] == str(rate)):
                    matched = True
    return False
