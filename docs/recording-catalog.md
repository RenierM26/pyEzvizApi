# Stored SD video: catalog and batch download

Current development-branch API. These commands query **camera SD recordings**,
not subscription cloud storage. Discovery supports the cloud v2 index or native
LAN-only HCNetSDK file search. LAN discovery and downloads require no account.

## 1. Query an explicit interval

Use UTC bounds, and the explicit IANA timezone used by the app's SD index and
native playback selectors. No host-local timezone is inferred. Naive index
strings are interpreted in this timezone; offset-bearing strings keep their
offset. Confirm this clock against your device/app before a large archive run.

```bash
pyezvizapi --token-file ezviz_token.json recordings list --serial SERIAL --channel 0 --begin-time 20261108T060000Z --end-time 20261109T060000Z --timezone Africa/Johannesburg --catalog recordings.json
```

The catalog contains normalized UTC intervals, serial, index channel and selector
timezone; no raw descriptors, URLs or keys. Multi-day queries are split into
one-day windows. Saturated responses are subdivided until below `--page-size`.
If even one second saturates, or `--max-queries`/`--max-records` is exceeded,
the command fails without replacing the catalog. This cannot prove the server
index includes every physical byte on the card. Malformed responses fail rather
than looking like an empty card. Intervals are clipped to the requested bounds,
sorted and deduplicated; overlapping distinct records are retained.

### Native LAN-only discovery

```bash
pyezvizapi recordings list --source lan-hcnetsdk --host 192.0.2.10 --serial SERIAL --lan-password-file device-password.txt --channel 1 --begin-time 20261108T060000Z --end-time 20261109T060000Z --timezone Africa/Johannesburg --catalog recordings.json
```

LAN searches accept at most 24 hours per invocation. They use the supplied
current device login password, not account credentials. Native start/record/end
markers, record counts and lengths are validated. No catalog is published until
the end marker and logout acknowledgement arrive. `--max-records` (10,000),
`--max-bytes` (1 MiB) and `--transfer-timeout` (60 seconds) bound the entire search.
An explicit empty native result succeeds; truncation, refusal or budget exhaustion
fails without replacing the catalog. No fallback or retries occur. Native
wall-clock timestamps use the explicit timezone; ambiguous clocks are rejected.
Single-record, 18-record and empty searches were compared with the native SDK
on H9c; other models are not hardware-qualified. This is file-index completeness,
not proof that every advertised interval is playable or that the card is healthy.

Catalogs retain `discovery: lan-hcnetsdk` and the one-based native channel. LAN
downloads default to that channel; cloud downloads of LAN catalogs require an
explicit `--cloud-channel` because channel numbering differs by route. Existing
`cloud-sd-v2` catalogs remain readable.

## 2. Download every catalog interval

LAN, using the **current device login password**, not the account password or
necessarily the printed verification code:

```bash
pyezvizapi recordings download --catalog recordings.json --source local-playback --host 192.0.2.10 --lan-password-file device-password.txt --local-channel 1 --output archive
```

Cloud-mediated camera SD playback (account required):

```bash
pyezvizapi --token-file ezviz_token.json recordings download --catalog recordings.json --source cloud-playback --media-key-file recording-key.txt --output archive
```

Use `--source both` with both sets of credentials to download every interval
sequentially over each route. There is no fallback between routes. LAN defaults
to the LAN catalog channel (otherwise 1); cloud catalogs default to their
catalog channel (commonly 0). Override with
`--local-channel`/`--cloud-channel`; these channel numbers are not interchangeable.
On the tested H9c, LAN channel 1 carries one video track plus audio; the cloud
route carries two video tracks plus audio. This tool does not invent missing
tracks or equate the resulting files.

Cloud video and audio decryption default on. Supply a private `--media-key-file`
to avoid recording-key lookup, or allow the existing account helper to obtain
it (which can require MFA). `--no-decrypt` explicitly preserves encrypted media.
Never commit password/key files or private catalog/manifest data.

## Completion and resume

Each route uses the existing complete-range validation and atomic file publish.
Every clip has a finite `--max-bytes` (default 128 MiB) and
`--transfer-timeout` (default 60 seconds); `--max-clips` defaults to 10,000 per
route. These are per-clip bounds, not a total archive disk/time budget. Long
recordings may need higher limits. Each interval must fit the existing 24-hour
playback selector. Run only one writer per output directory at a time.

Files have deterministic route/profile/interval names. A private atomic JSON
manifest records successful file hashes, byte counts, and failure categories or
numeric device codes. Repeating the command skips only files matching a success
receipt **and** their current SHA-256. Missing files are downloaded again;
modified files or existing files without receipts are reported as conflicts and
never overwritten. Inspect/move conflicts before retrying. Interruptions may
leave an already published file without its receipt: it is intentionally treated
as a conflict, not trusted as complete. Do not modify files during a run.

A refused/missing clip does not stop remaining downloads. Exit code 1 means at
least one interval failed/conflicted; exit code 0 means every interval in this
catalog was downloaded or hash-verified. An empty catalog succeeds without
media requests. This is not proof every catalog entry is playable: known H9c
intervals can be listed yet refused by both Python and the official app. Failures
are not silently skipped, and no retries or device settings changes are made.

## Python

```python
from pyezvizapi.streaming.recordings import query_recordings, download_recordings

# `client` is an already configured EzvizClient.
catalog = query_recordings(
    client, "SERIAL", "20261108T060000Z", "20261109T060000Z",
    timezone="Africa/Johannesburg",
)
report = download_recordings(
    client, catalog, "archive", source="cloud-playback", media_key="PRIVATE_KEY",
)
```

For account-free discovery:

```python
from pyezvizapi import HcNetSdkLanEndpoint, query_lan_recordings

catalog = query_lan_recordings(
    HcNetSdkLanEndpoint("SERIAL", "192.0.2.10"), "DEVICE_PASSWORD",
    "20261108T060000Z", "20261109T060000Z",
    timezone="Africa/Johannesburg",
)
```

See [media saving](media-saving.md) for single-interval APIs and existing
validation/decryption limits.

## Implementation boundaries

`streaming.recordings` remains the compatibility entrypoint. Internally, catalog
values live in `streaming.recording_models`, cloud index queries in
`streaming.cloud.recordings`, and native queries in `streaming.local.recordings`.
`streaming.recording_batch` owns sequential acquisition;
`streaming.recording_store` owns deterministic filenames, atomic manifests and
hash-verified resume. Catalog version 1, manifest contents and receipt identities
are unchanged by this separation. Clock helpers live in `streaming.ranges`.
