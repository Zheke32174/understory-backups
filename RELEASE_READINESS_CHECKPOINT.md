# Release-readiness checkpoint

## Identity

- Repository: `Zheke32174/understory-backups`
- Checkpoint branch: `security/public-signing-containment-v1`
- Reviewed default head: `f84c26cdd97890eeb8041e7b8a21030b7576c2e1`
- Validated implementation head: `fd94ea1f70a71931a53990bb8ce5bc35866234c1`
- Coordination: `Zheke32174/understory-common#3`

## Last completed scope

Public signing identity, APK publication authority, current-tree key exposure,
install-verification claims, vendored trust primitives, debug assembly, unit
tests, security reporting, and licensing presence.

## Resolved on this draft

- Removed the shared public debug private key from the current tree.
- Removed committed debug-signing configuration.
- Revoked debug signatures for authorship, sibling identity, and capabilities.
- Replaced automatic latest-release publication with read-only validation.
- Removed tag force-update and release-asset overwrite authority.
- Corrected install-verification and public-distribution claims.
- Added security guidance, incident provenance, key ignore rules, and a
  deterministic signing-boundary validator.
- Verified the repaired tree assembles and its unit tests pass.

## Validation receipts

GitHub Actions run `29918156525` passed at implementation head
`fd94ea1f70a71931a53990bb8ce5bc35866234c1`:

- immutable read-only checkout;
- public signing-boundary validation;
- Android SDK provisioning;
- debug APK assembly without a committed suite signing key;
- complete Gradle unit-test execution.

## Changed conclusion

The current source and validation boundary is green. The repository is not
publishable because historical artifacts, release governance, licensing, and an
authorized signed candidate remain unresolved.

## Open blockers

- The key remains reachable in public history and prior artifacts/releases.
- Existing movable tags and release assets need an explicit steward disposition.
- No independently verified signed release candidate exists.
- No immutable versioned publication workflow is approved.
- The repository has no explicit license; no license was invented.
- Offline release-key custody remains unverified.
- Branch rules, secret scanning, push protection, private vulnerability
  reporting, and immutable-release settings need administrative verification.
- All sibling repositories must integrate the same boundary before the suite can
  claim coordinated release identity.

## Reconsideration triggers

New commit, changed CI, newly discovered key material, changed release asset,
license decision, signing rotation, changed public claim, changed repository
visibility, or explicit steward request.

## Next action

Review the coordinated sibling receipts, select a source license, and decide the
disposition of prior public debug releases before designing any authenticated
release candidate.
