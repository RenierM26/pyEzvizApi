# pyEzvizApi 2.5.1 release notes

Patch release prepared from merged [#446](https://github.com/RenierM26/pyEzvizApi/pull/446)
on 2026-11-16. Check [GitHub](https://github.com/RenierM26/pyEzvizApi/releases/tag/v2.5.1)
and [PyPI](https://pypi.org/project/pyezvizapi/2.5.1/) for publication status.

## Image-position PTZ correction

- Include `zoomType: "zoomIn"` in the point payload, matching the retained Android
  app's complete `PTZManualCtrl/CtrlPTZ3DPosition` request.
- Reject boolean and non-numeric coordinates before transport. Coordinates remain
  normalized image positions in 0–1, not absolute pan/tilt angles.
- Preserve the existing full-unit rectangle, default and caller-selected routes,
  public method signatures and SDK error propagation.

See [point PTZ contracts](ptz-point-control.md) for app evidence and route details.
The field omission is an app-contract mismatch; offline evidence does not prove
that a particular camera fails without it or physically reaches a requested point.

## Compatibility

Python 3.12+ and dependencies are unchanged. No public APIs are removed and no
migration is needed for valid numeric calls. Callers that passed boolean or
non-numeric coordinates now receive `PyEzvizError` without a cloud request.
The [2.5.0 compatibility notes](release-2.5.0.md) still apply when upgrading from
an older version. No streaming, authentication or push behavior changes.

## Qualification and consumer adoption

The feature head passed 6,588 offline tests and 29 installed-wheel cases, with all
nine hosted checks green. The release preparation must pass its own CI, CodeQL
quality gate and Release Check before publishing through the normal workflow.
No live device commands or physical PTZ validation are part of release checks.

Companion [ha-ezviz #262](https://github.com/RenierM26/ha-ezviz/pull/262) must qualify
the published 2.5.1 wheel through its ordinary dependency profiles before becoming
ready. This SDK release does not deploy or release the HA integration.
