# September 7 review follow-up

## Source identity

Brain and SSWP use the same source-selection contract: include every tracked Git file, even when it is under `data/` or matches an ignore rule, plus nonignored new inputs outside known runtime/dependency directories. Git-ignored generated outputs are not source inputs. Tracked files always take precedence over exclusions. Deleted inputs change the digest. Non-Git folders use a conservative filesystem snapshot. Symlinks and submodules require an explicit packaged source snapshot rather than silently receiving partial coverage.

This closes both an omitted-input defect and the opposite false-positive defect in which ordinary ignored build output caused SOURCE_BYTES to fail. Python and Node manifests are tested against each other. Their shared source hashing must be upgraded together. Python Git commands explicitly disconnect stdin from MCP's transport to avoid the Windows subprocess hang reproduced during final integration.

## Approval policy

An unavailable unrelated root in `witness_roots` no longer prevents a valid registered project from being witnessed. The requested root must still exist and match an available policy entry. This does not broaden permissions or relax receipt authentication, expiry, source binding, argument binding or one-use replay rejection.

## Shipped bundles and build receipts

`build.mjs` records its own bytes, package configuration, TypeScript configuration, lockfile, all bundled source inputs and all seven generated bundles. Each bundle is built twice from identical inputs. `node scripts/verify-build-receipt.cjs` verifies the complete recorded source and artifact set, not only the MCP server bundle. CI must verify the committed receipt before rebuilding and check every generated bundle for drift after rebuilding.

An internally consistent receipt is not a signature from an independent builder. The separate project reproducibility gate still requires two fresh source copies and declared nonempty outputs; same-host checks are not hermetic or cross-host proof.

## Validation and deployment

The regression suite includes tracked data changes, ignored generated output, force-tracked ignored inputs, Python/Node digests, unavailable policy roots, changed receipt hashes, subprocess timeouts, missing evidence, nested attestation changes and replay. Cross-system tests exercise actual stdio MCP requests, Brain-issued receipts, SSWP evidence, automatic Steno delivery, task isolation and v2 integrity.

Use the exact companion revisions recorded in `.github/workflows/ci.yml` as the tested interoperability baseline. Updating repositories does not refresh an already running Codex process. Deployment must restart all three with the same shared-state directory and task identifiers, then repeat a synthetic task flow. Repository tests do not inspect or certify the operator's live databases or Drive recovery archive. Historical records remain preserved and explicitly unverified.
