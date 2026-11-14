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

## Consumer failures

A cloud HTTP 200 body is not necessarily a usable JPEG. Consumers must not label
or cache ciphertext as `image/jpeg` after a decoder failure or missing key.
The HA companion fix rejects such responses, evicts encrypted cached content and
allows a subsequent request to recover. Reload updated integration code to make
it active; neither these SDK changes nor the tests perform a live HA reload.
