# Utility contracts

The historical `pyezvizapi.utils` imports remain a compatibility facade. Imported
functions are the implementation objects, not wrappers:

| Family | Implementation | Contract |
| --- | --- | --- |
| Tolerant conversion | `_coercion` | `coerce_int` retains boolean and finite-float truncation; unconvertible/non-finite values return `None`. This is not a strict packet/count validator. |
| Nested mappings | `_mapping` | Missing traversal returns the caller's default. `deep_merge` combines dicts, concatenates lists and otherwise chooses the right operand. It does not mutate inputs or deep-copy unchanged subtrees. |
| Alarm/time | `_alarm_time` | UTC epochs are preferred (including zero), invalid/overflowing epochs can fall back to formatted time, and existing alarm tuple/motion-window semantics are preserved. |
| Image envelope | `_image_crypto` | Retains the proprietary header/password hash/CBC wire format, concatenated blocks and legacy partial trailing-byte alignment handling. Final plaintext padding must be valid PKCS#7. |

`decode_json` returns `None` for invalid JSON strings, not the original string.
`convert_to_dict` mutates only a dict's top-level string values; it is not a
recursive decoder. `string_to_list` splits only strings containing its separator.

IANA zones retain DST rules. Explicit fixed offsets stay fixed: an offset does
not identify a region. Offset hours must be below 24 and minutes below 60;
malformed/unavailable values use the documented local-timezone/UTC fallback.
This does not change the separate fixed-offset/DST proposal.

Typed `CaptureLimits` requires positive integer packet/byte counts, excluding
booleans, and positive finite numeric durations. Arbitrarily large positive
integer counts do not need conversion to float. `None` still means an unset
bound; callers requiring termination must call `require_bounded`. The legacy
positive-bound helpers and nonpositive-limit carrier are separate compatibility
contracts and are not substitutes for validating typed options.

`BoundedStderrTail.text(max_chars=0)` and negative limits return an empty string;
this does not erase retained bytes or change the independent byte-retention cap.
