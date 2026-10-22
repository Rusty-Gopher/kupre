# Contributing to kupre

## Before you start

Run `make check` (gofmt, vet, tests) and, with a disposable cluster such as
kind, `make integration`. CI runs both.

## The rule that matters most

**A check must never claim more than it measured.**

kupre is a preflight tool. A false negative — telling someone their cluster is
ready when it is not — is the worst thing it can do. Every check therefore
declares two things:

```go
Evidence: "Counts nodes that are Ready, uncordoned and free of NoSchedule taints.",
Limits:   "A node count is not a capacity model. This does not evaluate allocatable
           resources, pod requests, affinity, topology or local volumes.",
```

`Evidence` is what you actually inspected. `Limits` is what someone might
reasonably assume you inspected but did not. Both are shown to the user.

If a check cannot establish something, it must return `Skip` or `Warn` — never
`Pass`. "I found nothing" and "there is nothing" are different claims.

## Adding a check

1. Add it to the right family (`WorkloadChecks()`, `NodeChecks()`, …) so
   `AllChecks()` picks it up.
2. Set `Severity` (does a failure block the upgrade?) and `Action` (what kind of
   work does it demand, and when?). Omitting `Action` files the finding under
   "not blocking this upgrade" — `TestEveryCheckDeclaresAction` will fail.
3. Write `Evidence` and `Limits`.
4. Always attach `WithRemediation`. `TestFindingsCarryRemediation` enforces it.
5. Only attach `WithCommands` when the command is known to be correct for that
   specific cluster. An operator will paste whatever you print. See
   `scaleCommandsFor` for the reference treatment, including how it refuses to
   suggest a scale when the real problem is an unhealthy pod.
6. Add a fixture in `testdata/` and a case in `TestChecksAgainstFixtures`.

## Updating the deprecation database

Only add removals that **have shipped in a released version**. Upstream
announcements slip: the 1.33 changelog said `resource.k8s.io/v1beta1` would be
removed in 1.36, and it was not.

When adding a release, bump `DataHorizon` and `DataHorizonVerified` in the same
commit. Checks that consult the database must call `deprecation.BeyondHorizon()`
and degrade rather than reporting a clean result for a version they know nothing
about.

## Cluster safety

Only `Get` and `List`. No `Create`, `Update`, `Patch`, `Delete` or
`Apply` anywhere in `pkg/` or `cmd/`. If a check needs data that would require a
write, the check does not get written.
