# pyEzvizApi 2.4.0 release notes

Prepared from merged main through #442 on 2026-11-14. Check
[GitHub releases](https://github.com/RenierM26/pyEzvizApi/releases/tag/v2.4.0)
and [PyPI](https://pypi.org/project/pyezvizapi/2.4.0/) for publication status.

## Why a minor release

New public image-record and key-mode APIs accompany the framing correction in
#441 and app image variants in #442. Python 3.12+ remains required. Existing
bytes-returning APIs and ASCII text-key behavior remain compatible.

## Image decoding

- Parse declared multi-image boundaries before AES so opaque headers/trailers
  are not mistaken for ciphertext. Retain password, alignment and PKCS7 checks;
  malformed later records fail the whole response.
- Decode clear/encrypted `hikpic`, `hiklittlepic`, `mutichhiklit`-family and
  `mutichhikpic` envelopes. Clear multi-image selection works without a key.
- Add explicit `ImageKeyMode.HEX`, caller-owned known text `key_candidates`,
  UTF-8 byte-sized text keys and structured `decode_image_records` results with
  channel IDs, repeated records and bounded detection metadata.
- Restrict JPEG splitting and heuristic composite cropping to JPEG payloads.
  Recognized non-JPEG bytes pass through; no PNG transcoding is introduced.

See [image decoding](image-decryption.md) for exact contracts and cached APK
provenance. Observed cloud samples are JPEG; the app's local PNG encoding is not
proof of PNG cloud responses. Synthetic fixtures do not prove firmware support
for non-ASCII passwords. No key guessing, default-password fallback, key storage
or live device operations are added.

## Qualification and consumer update

The reviewed feature head passed 6,445 tests (91.58% coverage), 215 image cases
from a fresh wheel, 490 focused SDK checks, 27 real-HA worker/cache checks and
all nine hosted checks, with clean Codex review. Release preparation must pass
its own CI and Release Check before publication.

Install `pyezvizapi[images]==2.4.0` for optional Pillow processing. Async callers
still own workers, caching and lifecycle. The companion
[ha-ezviz #253](https://github.com/RenierM26/ha-ezviz/pull/253) must independently
qualify the published artifact and update its dependency pin. This release does
not deploy HA or establish coexistence with HA's stock SDK pin. Users upgrading
from 1.x must also follow the [2.0 migration](release-2.0.0.md).
