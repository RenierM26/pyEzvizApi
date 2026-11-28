# Documentation

These guides track `main`. For an installed PyPI version, use the docs at its
[matching release tag](https://github.com/RenierM26/pyEzvizApi/releases). See the
[changelog](../CHANGELOG.md) for shipped changes and upgrade notes.

## Start by task

| I want to… | Start here |
| --- | --- |
| Install, sign in, and list devices | [Getting started](getting-started.md) |
| Integrate the Python SDK: sign in, persist tokens, and poll device state | [Python API](python-api.md) |
| Use the command line | [CLI guide](cli.md) |
| Fix sign-in, MFA, or token errors | [Getting started troubleshooting](getting-started.md#common-problems) and [login recovery](auth/login-recovery.md) |
| Receive push notifications or migrate an old push token | [Channel-99 push](channel99.md) |
| Use the SDK with Home Assistant | [Home Assistant integration status](home-assistant.md) |
| Stream video or save images and recordings | [Media paths](media.md) |
| Upgrade from 1.x or replace removed imports | [2.0 upgrade notes](release-2.0.0.md) and [import compatibility](ha-compatibility.md) |

## Devices, inventory, and controls

- **Read state:** [Typed device inventory](device_inventory.md),
  [pagelist API](pagelist-api.md), [reported settings and write routes](pagelist-state.md),
  [detectors](detectors.md), and [alarm/message history](unified-message-list.md).
- **Control cameras:** [Camera channels](camera-channels.md),
  [cloud PTZ](ptz-app-controls.md), [point-based PTZ](ptz-point-control.md), [device switches](device-switches.md),
  [AI detection](ai-detection.md), [image controls](image-controls.md), and
  [recording, patrol, privacy, and audio controls](camera-app-controls.md).
- **Use an intercom:** [Intercom inventory, settings, and events](intercom.md)
  and [HPD7 door/gate routing](hpd7-unlock-routing.md).

## Integration and maintainer references

- **Authentication:** [Login and MFA recovery](auth/login-recovery.md), and
  [persisted installation identity](auth/persisted-client-identity.md) for
  containers and other hosts whose MAC address may change.
- **Home Assistant:** [Integration contract](home-assistant-contract.md),
  [feature boundaries](ha-feature-boundary.md), and
  [pinned custom integration acceptance](../examples/ha_ezviz/README.md).
- **Implementation:** [Code map](code-map.md),
  [bootstrap and pagination](bootstrap-and-pagination.md),
  [utility contracts](utility-contracts.md), and
  [observed Home Assistant regressions](ha-observed-error-regressions.md).
- **Project maintenance:** [Contributing](../CONTRIBUTING.md),
  [release process](releases.md), [repository watch agent](repo-watch-agent.md),
  [support](../SUPPORT.md), [security](../SECURITY.md), and [license](../LICENSE).

## Development media and protocol guides

See the [development media index](development-and-evidence.md#development-media-and-protocol-guides)
for advanced stream APIs, playback experiments, and native validation recipes.
These are not ordinary install paths or claims of production playback support.

## Historical plans and qualification evidence

See the [evidence index](development-and-evidence.md#historical-plans-and-qualification-evidence)
for pinned test reports, source-review proposals, and earlier implementation
plans. Archived evidence describes the inputs and revisions it names, not what
a current installation necessarily supports.
