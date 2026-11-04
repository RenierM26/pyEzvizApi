"""Non-acquiring receive-codec preflight; the provider still validates full SDP."""
from __future__ import annotations

_DIRECTIONS = {"sendrecv", "recvonly", "sendonly", "inactive"}


def receives_codec(offer: str, kind: str, codec: str, rate: int) -> bool:
    """Require a listed codec in a non-rejected media section that can receive."""
    session_direction = "sendrecv"
    direction = session_direction
    payloads: set[str] = set()
    active = matched = False
    in_media = False
    for raw in (*offer.splitlines(), "m="):
        line = raw.strip()
        if line.startswith("m="):
            if active and matched and direction in {"recvonly", "sendrecv"}:
                return True
            fields = line[2:].split()
            in_media = True
            port = fields[1].split("/", 1)[0].lstrip("0") if len(fields) > 1 else ""
            active = (len(fields) >= 4 and fields[0] == kind
                      and 0 < len(port) <= 5 and port.isascii() and port.isdecimal()
                      and 0 < int(port) <= 65535
                      and "RTP" in fields[2].split("/"))
            payloads = set(fields[3:]) if active else set()
            direction, matched = session_direction, False
        elif line.startswith("a=") and line[2:] in _DIRECTIONS:
            direction = line[2:]
            if not in_media:
                session_direction = direction
        elif active and line.startswith("a=rtpmap:"):
            mapping = line[len("a=rtpmap:"):].split()
            if len(mapping) == 2 and mapping[0] in payloads:
                encoding = mapping[1].split("/")
                if (len(encoding) >= 2 and encoding[0].casefold() == codec.casefold()
                        and encoding[1] == str(rate)):
                    matched = True
    return False
