```
    __
   / /___  ______  ________
  / //_/ / / / __ \/ ___/ _ \
 / ,< / /_/ / /_/ / /  /  __/
/_/|_|\__,_/ .___/_/   \___/
          /_/
  KUBERNETES PREFLIGHT & REVIEW ENGINE
```

[![CI](https://github.com/Rusty-Gopher/kupre/actions/workflows/ci.yml/badge.svg)](https://github.com/Rusty-Gopher/kupre/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Rusty-Gopher/kupre)](https://github.com/Rusty-Gopher/kupre/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Kubernetes upgrade preflight, health check and certificate audit for live
clusters. Read-only, single binary. Pick a mission:

- **Upgrade preflight**: is this cluster ready for a target version?
- **Health check**: what is broken right now, and why?
- **Certificate audit**: what certificates exist, when do they expire?

Problems come out as a worklist, ordered by what to fix first. Every scan also
saves a shareable HTML report next to where you ran it.

## Install

Prebuilt binaries for Linux, macOS and Windows are on the
[releases page](https://github.com/Rusty-Gopher/kupre/releases) — download,
unpack, run `./kupre`. Every release ships checksums, an SBOM and a build
attestation.

With Go 1.26+ installed:

```bash
go install github.com/Rusty-Gopher/kupre/cmd/kupre@latest
```

Or from source:

```bash
git clone https://github.com/Rusty-Gopher/kupre.git
cd kupre
make tui       # builds and starts the interactive mode
```

`make build` compiles `./kupre` without starting it.

## Run it

Running `kupre` with no arguments starts the interactive mode:

1. Intro screen. Press enter.
2. Pick a mission.
3. Pick a kubeconfig from the list, or press `e` to type a path.
4. Pick a cluster if the file has more than one.
5. Upgrade preflight only: type the target version, like `1.36.0`. The current
   version is read from the cluster, you never enter it.
6. Browse the results. The saved report path is shown under the verdict.

Keys in the results screen:

| Key | Action |
|-----|--------|
| up / down | move between findings |
| enter | open a finding: resources, fix steps, exact kubectl commands |
| p | show passing checks |
| r | scan again after a fix |
| q | quit |

Loop: fix the top item, press `r`, repeat until the verdict says ready.

## What it needs

A kubeconfig. That is the only input. Any cluster the kubeconfig can reach
works: managed offerings like EKS, GKE, AKS or MetaKube, self-managed kubeadm,
on-prem, k3s, kind.

Provider-specific checks activate only where they apply. On an OpenStack-based
cluster the Cinder and Octavia checks run; on a kubeadm cluster the kubeadm
config checks run; everywhere else they stay silent. The core checks are the
same on every cluster.

## Scripts and CI

```bash
kupre check --target-version 1.36.0    # upgrade preflight, exit code is the verdict
kupre health                           # health check
kupre certs                            # certificate audit
kupre fleet --target-version 1.36.0    # every kubeconfig context
kupre checks -v                        # list all checks, no cluster needed
```

- Output formats: `table`, `flat`, `json`, `markdown`, `html`.
- `-o html` in a terminal writes `kupre-<mission>-report.html` and prints the
  path; redirected output streams as usual.
- Exit codes: 0 ready, 1 blocking, 2 warnings only, 3 scan failed. A failed
  scan is never reported as ready.

## How it compares

kubent, Pluto and kubepug answer one question: which deprecated APIs are in
use. Popeye lints cluster health. kupre's job is the whole pre-upgrade
question — deprecated APIs are four of its 51 checks; the rest cover what
actually breaks upgrades: PDBs that block node drains, fail-closed webhooks on
single-replica backends, kubelet version skew, expiring certificates, CoreDNS
config migration, and provider-specific hazards (kubeadm, Cluster API,
OpenStack).

|  | kupre | kubent | Pluto | kubepug | Popeye |
|---|---|---|---|---|---|
| Deprecated APIs, live cluster | yes | yes | partial | yes | no |
| Helm release manifests scanned | yes | yes | yes | no | no |
| Drain blockers (PDBs), webhooks, node skew | yes | no | no | no | partial |
| Certificate expiry audit | yes | no | no | no | no |
| Health mission | yes | no | no | no | yes |
| Target-version preflight verdict | yes | no | no | yes | no |
| Deprecation data current | 1.37 | frozen at 1.32, unmaintained since Jan 2025 | current | current | n/a |

Two honest boundaries: scanning rendered manifests in CI *before* they reach a
cluster is Pluto's territory — kupre reads only live clusters. And no
live-object scan can prove deprecated API *usage* (the API server converts
objects on read), which is why kupre classifies evidence as confirmed versus
unknown instead of guessing — `kupre checks -v` shows what every check
measures and what it cannot.

## Permissions

- An admin kubeconfig works as is.
- For a limited account, apply `deploy/rbac.yaml`. Read access only, each rule
  says which checks need it.
- Checks without permission skip and name the missing permission.

## Development

```bash
make test      # unit tests, no cluster needed
make check     # format, vet, tests
```

New checks must not claim more than they measured.

MIT licensed.
