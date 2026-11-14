# devices

Device wrappers, status assembly and feature/payload interpretation. Account transport stays in `cloud`.

See [the code map](../../docs/code-map.md) for cross-domain navigation.

`detector.EzvizDetector` reads gateway-linked sensor `FEATURE_INFO` values without
camera requests or controls; see [detector support](../../docs/detectors.md).

Feature helpers are organized by responsibility: `capabilities`, `metadata`,
`ports`, `tracking`, `lens`, `audio` and `images`. The historical `controls`
module re-exports the same public objects for existing consumers. See
[the feature boundary guide](../../docs/ha-feature-boundary.md).
