# HPD7 gate/door unlock routing (issues #268 and #432)

## Confirmed library defect

The feature-action URL is:

```text
/v3/iot-feature/action/{serial}/{resourceIdentifier}/{localIndex}/DoorLockMgr/RemoteUnlockReq
```

`resourceInfos.resourceId` is an opaque resource-management ID. It is **not**
the feature namespace. Use `resourceInfos.resourceIdentifier` (`Video`,
`DoorLock`, etc.) with the associated `localIndex`. Previously the camera
wrapper used the opaque ID even when the identifier was available. This is
consistent with the server's "device feature not registered" error, but
physical HPD7 confirmation is still pending.

The correction prefers a nonempty string `resourceIdentifier`. It retains the
old `resourceId` fallback for legacy callers that stored the namespace there.
It applies to all four camera lock/unlock wrappers because they share routing.
The original #268 correction changed no bind-code, token, lock-number, or
resource-selection policy; the later #432 selection change is described below.

## Official app evidence

Static inspection of the retained Android decompilation shows:

- `BasePlayerOperationPresenter.v3()` (local gate) and `A1()` (local lock) send
  `RemoteUnlockReq` through `DevicePhysicalModelRepository.setAction`, with
  resource namespace `Video`, the player local index, and lock numbers 1 and 2
  respectively.
- `OpenGateRequestParams` initializes `streamToken` to an empty string. Those
  two methods set bind code, user name, and lock number but not stream token;
  they do not start a call as part of sending this action.
- The separate remote/linked-lock path in `onVerifyScreenPwdEvent()` uses the
  selected `RemoteUnlockEntity.getResourceIdentifier()` and local index. It
  also supplies a stream token. This path must not be conflated with the
  intercom's local gate/lock relay.
- `DevicePhysicalModelApi.setAction` and `DeviceControlApi.setAction` map to
  the same feature-action URL. A misleading Java parameter named `resourceId`
  does not mean that a resource-management ID belongs there.
- `ResourceInfo` stores `resourceId` and `resourceIdentifier` as separate fields.
  The repository's sanitized pagelist fixture also contains both fields.

This is static app evidence, not a captured HPD7 request or device success.
No proprietary app code or device credentials are included in this change.

## Validation and remaining limits

New offline tests exercise the public camera methods through the client's
request boundary: opaque resource ID versus namespace, Video and DoorLock,
list/mapping containers, local index zero, gate/door lock numbers, empty stream
token, rejected server response, and legacy fallback with token/type retained.

PR #404 independently fixes false success reporting for rejected controls.
This routing fix is based on that PR so a rejected request remains an error.

## Multi-resource intercom discovery (issue #432)

The #432 report explicitly lists SDK 2.0.0 and shows an action targeting
`global/0`. The 2.0.0 wrapper still selected the first discovery resource and can choose
`global` ahead of a later intercom `Video` entry. The earlier
resource-ID correction alone cannot fix this ordering defect.

For devices reported as `BDoorBell`, the camera lock/unlock wrappers now prefer
one explicitly reported `resourceIdentifier="Video"` entry, preserving that
entry's local index (including zero), stream token and type. Multiple `Video`
entries are rejected before terminal lookup or action IO: the caller must select
an explicit namespace/index through the low-level client. Other device categories
and legacy intercom data without an explicit `Video` entry retain their existing
routing behavior. No route is invented from the model name or `FEATURE_INFO`.
In particular, `DoorLockMgr` configuration also appears on ordinary cameras and
does not prove that a namespace supports a lock actuator.

Offline regressions reproduce the old `global/0` URL from global-first discovery,
then verify `Video/0` through both CLI unlock commands and all four camera lock
wrappers. Rejected server responses remain errors. This establishes a routing
correction, not successful physical operation: #432 does not include sanitized
resource metadata or a captured successful iOS request. Reporter confirmation
of the device category and `Video` entry, then physical qualification, remain
necessary before claiming the issue resolved. Terminal binding, permissions,
firmware and other causes of a generic `meta.code=400` remain separate.

The low-level
`remote_unlock(resource_id=..., local_index=...)` argument expects the **feature
namespace**, despite its historical name. The issue reporter's terminal-name
filtering problem is separate; passing `terminal_filter_name=None` remains the
existing opt-in for their standalone/Termux workflow.

Until the reporter verifies the corrected route on the actual HPD7, this is a
candidate fix, not proof that every cause of issue #268 is resolved. No account,
stream, call, or physical lock action was used during development.
