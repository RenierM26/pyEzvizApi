# Cloud image encryption and multi-image framing

`decrypt_image` accepts legacy `hikencodepicture` blocks and the observed
length-delimited `mutichhikpic` envelope. This is separate from JPEG framing:
EXIF thumbnails inside a JPEG are not additional cloud encryption records.

## Length-delimited envelope

The observed structure begins with 12 ASCII bytes `mutichhikpic` and two opaque
suffix bytes. Records start at offset 14. At each record start `p`:

| Relative offset | Width | Interpretation |
| --- | --- | --- |
| 0 | 4 | Opaque record metadata |
| 4 | 4 | Big-endian unsigned remaining-record length |
| 8 | 4 | Big-endian unsigned encrypted-block length |
| 12 | declared block length | Complete `hikencodepicture` block, including hash header |
| after block | bounded by record end | Opaque trailer |

The encrypted range is `[p + 12, p + 12 + encrypted_length)`. The next record
starts at `p + 8 + remaining_length`. Both bounds must fit the response and the
block must fit its record. The block must contain its encryption/hash header and
at least one aligned AES block. The parser requires the encryption magic at the
declared block start; it does not search ciphertext or trailers for more records.

The suffix, metadata and trailer bytes are not assigned version/count/ordinal/
zero-padding semantics from one observed sample. Trailer length is derived from
record extents, not hardcoded to six or eighteen bytes. Truncated/malformed later
records fail the entire image response rather than silently returning earlier
lenses. Password hashes and PKCS7 padding still must validate; there is no
padding-search recovery or ignored decryption failure.

## Compatibility and limits

Legacy bare/concatenated `hikencodepicture` blocks retain their existing behavior,
including arbitrary legacy preambles. The length-delimited path is selected only
by its recognized outer magic, before the old preamble trimming can discard it.
Existing unframed trailing-alignment handling is not used for framed records.
The SDK helper itself was unchanged between 2.2.0 and 2.3.0; the envelope bug was
exposed during current multi-lens qualification, not caused by an AES/Pillow
installation failure.

Offline fixtures create synthetic images, encryption and varied opaque framing.
They cover declared bounds, one/many records, variable trailers, malformed fields,
truncation, wrong keys/padding and encryption magic inside ciphertext/trailers.
No private images, hashes, keys, signed cloud URLs or authentication tokens are
stored in the fixtures. Live recovery of a particular installation remains
unverified until the corrected SDK is installed and its consumer cache is reset.

## App image variants and structured decoding

Install `pyezvizapi[images]` for `pyezvizapi.devices.images`. Envelope parsing,
AES and `EzvizClient.download_alarm_image` do not require Pillow. All CPU-bound
image work still belongs in a worker when called from an async application.

```python
from pyezvizapi import ImageKeyMode, ImageRecord
from pyezvizapi.devices.images import decode_image_records, process_image_bytes

# Use only credentials already known to the caller; the SDK does not persist
# history, try a default credential, rotate a key or mutate camera settings.
records: tuple[ImageRecord, ...] = decode_image_records(
    response_bytes, current_key, key_candidates=known_previous_keys
)
for record in records:
    consume(record.channel_id, record.image_data, record.detection_data)

# Occurrence is zero-based; lens/channel numbers remain one-based.
selected = process_image_bytes(
    response_bytes, current_key, 2, 2, image_index=0
)

# Only use this explicit mode when the upstream route declares a raw key.
records = decode_image_records(
    response_bytes, raw_16_byte_key_as_32_hex_characters, key_mode=ImageKeyMode.HEX
)
```

`decode_image_records` returns ordered, immutable records, retaining original
channel IDs and repeated images. It separates top-level JPEGs without splitting
EXIF thumbnails. Byte payloads are omitted from record reprs. A channel-indexed
envelope requires an exact channel and occurrence; missing values raise
`PyEzvizError`. An unspecified zero channel retains positional compatibility.
Unindexed raw images retain positional clamping and vertical composite cropping
in `process_image_bytes`. Unlike the old helper, clear images are unpacked and
selected even when no password is configured. A single channel-indexed record is
not heuristically split into additional channels.

`record_header` and `trailer` retain encoded bytes without interpreting unknown
fields. `detection_data` retains the bounded decrypted footer payload: image bytes,
metadata bytes, BE uint32 image length, BE uint32 metadata length, then `$`.
Both lengths must account for the entire decoded record. This is preservation,
not a face/detection schema or overlay renderer. Versioned auxiliary TLVs remain
in `trailer`, distinct from the decrypted footer. Framing and decryption of all
records must succeed before any result is returned.

### Route-specific envelopes

The follow-up parsers are based on cached Android `com.ezviz` **7.4.1.0421**,
version code **1676**, APK SHA-256
`90d1007934e7878f44b3e1f94b65ccd2d0a29f967b23882cd54c9e5e815fd663`.
This is not a fresh app download or proof of every firmware's format. Control
flow was checked against smali where JADX produced inverted branches.

| Family | Prefix and records | Auxiliary extent |
| --- | --- | --- |
| `mutichhikpic` | Existing 14-byte prefix and 12-byte records above | Proven remaining-record length; unknown trailer bytes stay opaque |
| `hikpic` | 6-byte magic, BE u16 version, one opaque byte, BE u32 block length, payload (13-byte header) | Version 2 has u16 type + u32 length + auxiliary data |
| `hiklittlepic` | 12-byte magic + u16 version; records: u32 opaque group field, u16 channel, u32 block length, payload | Version 3 has a type/length auxiliary block |
| `mutichhiklit` family | App recognizes 12 bytes, consumes six opaque continuation bytes and u16 version; records: two opaque bytes, u16 channel, u32 opaque group field, u32 block length, payload | Each record has a type/length auxiliary block |

Channel interpretation follows the app's message-loader route: the first u16 of
`mutichhikpic` record metadata, the u16 at record offset 4 in `hiklittlepic`, and
the u16 at offset 2 in `mutichhiklit`. These are not universal meanings for every
opaque metadata field or a reinterpretation of the low-level legacy decrypt API.
The `mutichhikpic` suffix remains opaque (`version=None`). No six-byte trailer,
frame count, alternative magic continuation or group-length semantics are guessed.

Source anchors in the cached decompile: `DecryptFileOpener.o/p/j` and its smali
for dispatch, clear-data bypass, hex-key conversion and footer handling;
`AlertImageLoader.GetImageData` and its smali for message-loader channel maps and
the alternate prefix; `DeviceInfoEx.getCloudSafeModePasswd` for hash-selected
credential history. Tests use generated images and public synthetic test keys,
not captured images or app/account credentials.

### Key modes and compatibility

Text mode selects a supplied key by the embedded vendor double-MD5 hash, then
encodes UTF-8, truncates to 16 bytes and zero-pads to 16 bytes. This corrects a
character-versus-byte sizing mismatch for multibyte inputs; actual device support
for non-ASCII credentials is not established. Explicit known candidates may
match different records' historical keys. Wrong keys and malformed PKCS7 padding
remain errors, never a reason to return ciphertext.

Hex mode corresponds to app `encryptType == 2`: exactly one explicit 32-hex-digit
key representing 16 raw AES bytes. It skips the 48-byte record header without
treating it as a text-password checksum, and uses the same CBC IV and strict
padding. The SDK deliberately rejects shortened, odd-length and non-hex keys
instead of copying permissive app conversion behavior. A hex-looking text key
stays a text key unless the caller explicitly requests hex mode.

`download_alarm_image` accepts the same key-mode/candidate options and returns
flattened decoded image bytes. It fetches a current cloud key only for encrypted
text-mode data lacking supplied credentials. Clear records and opaque trailer
magic do not trigger key acquisition. `decrypt=False` preserves the original
response bytes. The existing `decrypt_image(data, password)` remains the narrow
legacy encrypted helper; use the structured/high-level APIs for new variants.

## Consumer failures

A cloud HTTP 200 body is not necessarily a usable JPEG. Consumers must not label
or cache ciphertext as `image/jpeg` after a decoder failure or missing key.
The HA companion fix rejects such responses, evicts encrypted cached content and
allows a subsequent request to recover. Reload updated integration code to make
it active; neither these SDK changes nor the tests perform a live HA reload.
