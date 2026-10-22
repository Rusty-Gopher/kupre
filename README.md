<h1 align="center">kupre</h1>

<p align="center">
  <strong>Know before you upgrade.</strong><br>
  Kubernetes upgrade preflight, health check and certificate audit for live clusters.<br>
  Read-only. One binary. Verdicts you can put in CI.
</p>

<p align="center">
  <a href="https://github.com/Rusty-Gopher/kupre/actions/workflows/ci.yml"><img src="https://github.com/Rusty-Gopher/kupre/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Rusty-Gopher/kupre/releases"><img src="https://img.shields.io/github/v/release/Rusty-Gopher/kupre" alt="Release"></a>
  <a href="https://goreportcard.com/report/github.com/Rusty-Gopher/kupre"><img src="https://goreportcard.com/badge/github.com/Rusty-Gopher/kupre" alt="Go Report Card"></a>
  <img src="https://img.shields.io/badge/release%20data-Kubernetes%201.37-326ce5?logo=kubernetes&logoColor=white" alt="Release data: Kubernetes 1.37">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT"></a>
</p>

<p align="center">
  <img src="docs/demo/tui.gif" alt="kupre interactive mode: pick a mission and a cluster, get an ordered worklist, open a finding for the exact fix" width="900">
</p>

Most upgrade outages aren't caused by deprecated APIs. They're caused by a
PodDisruptionBudget that stalls the drain, a fail-closed webhook with one
replica, a kubelet flag the new version rejects, or a certificate that expires
mid-rollout. kupre checks all of that against the live cluster. It returns an
**ordered worklist**: what blocks the upgrade, what needs lead time, and what
only a human can verify. Each item comes with the exact `kubectl` command
that fixes it.

```text
$ kupre check --target-version 1.37.0

cluster demo   upgrade v1.36.4 → v1.37.0
NOT READY - 1 blocking, 8 to review

BLOCKS THE UPGRADE: fix before you start
  1. 1 PodDisruptionBudget(s) allow zero disruptions and will block node drain
     · shop/checkout (PodDisruptionBudget)  minAvailable=1, healthy 1/1, disruptionsAllowed=0
     $ kubectl scale deployment/checkout -n shop --replicas=2

START NOW: these need lead time
  2. ingress-nginx is in use (0 controller pod(s), 1 IngressClass(es), 1 Ingress(es)); it was
     retired in March 2026 and gets no more security patches
  ...
```

## Why kupre

- **The whole upgrade question, not one slice of it.** 61 checks across
  removed APIs (live objects *and* Helm release history), drain blockers,
  webhooks, version skew, CoreDNS migration, kubelet and feature-gate
  breakage, end-of-life dates, certificates, and provider-specific hazards
  for kubeadm, Cluster API and OpenStack.
- **Release data that keeps up.** Kubernetes 1.37 data shipped with every
  entry checked against the upstream changelog. A target beyond kupre's data
  is reported as *unknown*, never as clean.
- **"Couldn't check" is never "pass".** Forbidden lists, missing permissions
  and failed discovery become *skipped* or *inconclusive*, by name. This is
  tested end to end, including a service account with no permissions at all.
- **Every claim states its evidence and its limits.** `kupre checks -v`
  shows what each check inspects and what it cannot conclude.
- **Read-only by construction.** It only issues `get` and `list` calls, and
  CI fails the build if a write call ever appears in the code.
  [`deploy/rbac.yaml`](deploy/rbac.yaml) is the complete grant it needs.
- **Built for teams:** exit codes, versioned JSON, a GitHub Action,
  expiring waivers, and baselines so CI fails only on *new* problems.

## Install

```bash
# Prebuilt binaries: Linux, macOS, Windows (amd64, arm64)
# https://github.com/Rusty-Gopher/kupre/releases

# Go 1.26+
go install github.com/Rusty-Gopher/kupre/cmd/kupre@latest

# Homebrew (macOS, Linux)
brew install rusty-gopher/tap/kupre

# krew: then run it as `kubectl kupre`
kubectl krew index add rusty-gopher https://github.com/Rusty-Gopher/homebrew-tap
kubectl krew install rusty-gopher/kupre

# Container image (multi-arch, distroless, non-root)
docker run --rm -v ~/.kube:/home/nonroot/.kube:ro ghcr.io/rusty-gopher/kupre health
# (add --network host for a cluster on localhost, such as kind)
```

Every release ships checksums, SBOMs and a signed build-provenance
attestation: `gh attestation verify --owner Rusty-Gopher <file>`.

## Quick start

```bash
kupre                                   # interactive: pick a mission and a cluster
kupre check --target-version 1.37.0     # upgrade preflight
kupre health                            # what is broken right now, and why
kupre certs                             # every certificate kupre can see, and when it expires
kupre fleet --target-version 1.37.0     # every context in your kubeconfig
kupre checks -v                         # all 61 checks, no cluster needed
source <(kupre completion bash)         # or zsh, fish, powershell
```

The only input is a kubeconfig. kupre works with any cluster it can reach:
EKS, GKE, AKS, kubeadm, Cluster API, OpenStack, k3s, kind. Provider checks
only switch on when their platform is detected.

| Mission | Answers | Typical finding |
|---|---|---|
| `check` | Is this cluster ready for version X? | PDB blocks drain · removed API in a Helm release · kubelet flag removed in the target version |
| `health` | What is broken right now, and why? | CrashLoop with the cluster's own reason · stuck rollout · release past end of life |
| `certs` | What expires, and when? | Webhook CA bundle expiring · TLS Secret expired · cert-manager renewal failing |

## In CI

<p align="center">
  <img src="docs/demo/cli.gif" alt="kupre in scripts: JSON verdict and exit code, then a baseline so only new problems fail" width="900">
</p>

**Exit codes are the verdict:** `0` ready · `1` blocking · `2` warnings only ·
`3` scan could not complete. A failed scan is never reported as ready.

### GitHub Action

```yaml
- uses: Rusty-Gopher/kupre@v0.2.1
  with:
    target-version: 1.37.0          # mission: check (default) | health | certs
    fail-on: blocking               # blocking (default) | warnings | never
    baseline: kupre-baseline.json   # optional: fail only on new findings
```

The action writes the report to the job summary and sets `verdict`,
`exit-code` and `report` (the JSON path) as outputs. It reads
`$KUBECONFIG`, or whatever you pass as `kubeconfig:`.

### Output formats

`-o table` (the worklist) · `flat` · `json` · `markdown` · `html`.
`--json-file report.json` also saves the full JSON report, whatever format
goes to stdout. The JSON carries `schemaVersion`. Fields may be added within
a version; any rename or removal bumps it.

### Policy: waivers, overrides, baselines

Put a `.kupre.yaml` next to where kupre runs, or pass `--policy path`:

```yaml
version: 1
disable: [missing-resource-requests]      # still reported, as skipped
severity:
  single-replica-workloads: info          # recorded on the finding
waivers:
  - check: legacy-endpoints
    resources: [{namespace: shop, name: legacy-api}]   # omit to waive the whole check
    reason: migrating to EndpointSlice in Q1
    owner: team-shop
    expires: 2026-12-31                   # required; expired waivers stop applying, loudly
```

`--baseline previous.json` accepts warnings that were already there, so a
pipeline fails only on what's new.

Some rules never bend:
- **A blocker cannot be waived or baselined.** Accepting one takes an
  explicit severity override, and that override is printed on the finding.
- **Accepted findings stay visible** in their own section of the report.
- **A waiver scoped to specific resources** doesn't cover a new offender of
  the same check.
- **A typo in the policy file fails the run** (exit 3) instead of silently
  doing nothing.

## In the cluster

A nightly read-only health check, with JSON in the pod log:

```bash
kubectl apply -f deploy/rbac.yaml -f deploy/cronjob.yaml
```

## Permissions

An admin kubeconfig works as is. For least privilege, apply
[`deploy/rbac.yaml`](deploy/rbac.yaml). It grants only `get` and `list`,
and each rule names the checks that use it. Checks without permission skip
and name the missing permission. CI proves on every commit that this RBAC is
enough for a complete scan.

## How it compares

|  | kupre | kubent | Pluto | kubepug | Popeye |
|---|---|---|---|---|---|
| Removed APIs, live cluster | ✅ | ✅ | partial | ✅ | — |
| Removed APIs in Helm releases | ✅ | ✅ | ✅ | — | — |
| Drain blockers, webhooks, version skew | ✅ | — | — | — | partial |
| Kubelet, feature-gate and kubeadm breakage per release | ✅ | — | — | — | — |
| Certificate audit | ✅ | — | — | — | — |
| Health mission | ✅ | — | — | — | ✅ |
| Waivers with expiry, baselines | ✅ | — | — | — | — |
| Release data | 1.37 | frozen at 1.32 | current | current | n/a |

Two honest boundaries. Scanning rendered manifests in CI *before* they reach
a cluster is Pluto's job; kupre reads live clusters. And no scan of live
objects can prove *usage* of a deprecated API version, because the API server
converts objects on read. So kupre reports confirmed and unknown evidence
separately instead of guessing.

## Development

```bash
make check         # format, vet, unit tests
make integration   # end to end against $KUBECONFIG (CI runs kind 1.35-1.37)
```

New checks must state their evidence and limits, and must not claim more
than they measured. Release data must quote its upstream source. To
re-record the demos, see [`docs/demo/`](docs/demo/).

MIT licensed.
