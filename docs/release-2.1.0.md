# pyEzvizApi 2.1.0 release notes

Prepared from merged main through PR #434 on 2026-11-14. This is release
preparation, not publication or deployment. Check [GitHub releases](https://github.com/RenierM26/pyEzvizApi/releases)
and [PyPI](https://pypi.org/project/pyezvizapi/) for actual availability.
Update the preparation date before publication on a later date.

## Why a minor version

2.1.0 adds an opt-in public identity API and a scoped intercom routing correction
on top of 2.0.0. Python 3.12+ remains required; no new dependency or additional
import removal is introduced. Users upgrading from 1.x must still follow the
[2.0 migration notes](release-2.0.0.md).

## Persisted installation identity (#433)

`EzvizClient`, `MQTTClient` and `EzvizCAS` accept `feature_code=`. The selected
identity is exposed as the read-only `EzvizClient.feature_code` property. An
application can persist an identity independently of its container's MAC and
supply it on login, MFA retries, refresh and credential restoration.

- Persist the identity atomically **before first login**, and persist the complete
  token/push state through `on_token_updated` as before.
- Explicit identities must be 32 lowercase hexadecimal characters. Existing
  trusted tokens can provide an identity to explicitly adopt; do not rewrite a
  token's binding or share replay state between concurrent deployments.
- Omitting the argument retains MAC-derived defaults. Saved tokens do not silently
  select an identity. Expiry, revocation and MFA remain applicable.
- This SDK release alone does **not** change CLI or Home Assistant persistence.
  Each consumer needs deliberate adoption and a compatible dependency requirement.

See [identity ownership and migration](auth/persisted-client-identity.md).
Offline controls cover fresh-process token restoration with different synthetic
MACs, login/MFA/refresh, HTTP/push/CAS propagation and independent clients. They do
not establish live cloud or container-recreation reliability for every consumer.

## Intercom relay resource selection (#434; related to #432)

For `BDoorBell` devices, camera gate/door actions prefer a unique explicitly
advertised `Video` resource instead of the first discovery entry (which can be
`global`). Its local index, stream token and type are retained. Multiple `Video`
entries raise an actionable error before IO rather than guessing a relay.
Other categories and legacy data without an explicit `Video` entry retain their
existing routing. Terminal binding, lock numbers and response acceptance do not
change; no fallback to the other physical relay is added.

The official Android app trace corroborates the `Video` namespace and selected
resource index. Physical HPD7 confirmation for #432 remains pending; do not treat
a generic meta=400 as proof of this sole cause. See the
[routing investigation and limits](hpd7-unlock-routing.md).

## Maintenance

The pinned `requirements.txt` snapshot updates Paho MQTT to 2.2.0 and PyCryptodome
to 4.3.0 (#431), and CI updates `actions/setup-go` to v7 (#430). Package runtime
requirements remain those declared in `pyproject.toml`.

## Maintainer publication checklist

1. Review and merge the release-preparation PR with required CI and the separate
   CodeQL quality gate passing at its exact head.
2. Run **Release Check** on merged main with `release-tag=v2.1.0`; inspect its
   checked distributions. No tag or PyPI upload occurs in this check.
3. Only when publication is authorized, run **Upload Python Package** with bare
   version `2.1.0`. Do not separately create a published GitHub release: that is
   another publishing trigger.
4. Verify the installed PyPI distribution and matching GitHub tag/release, then
   update consumer integrations separately. See [release procedure](releases.md).
