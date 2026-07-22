```
    __
   / /___  ______  ________
  / //_/ / / / __ \/ ___/ _ \
 / ,< / /_/ / /_/ / /  /  __/
/_/|_|\__,_/ .___/_/   \___/
          /_/
  KUBERNETES PREFLIGHT & REVIEW ENGINE
```

kupre analyzes live Kubernetes clusters, read-only. Pick a mission:

- **Upgrade preflight**: is this cluster ready for a target version?
- **Health check**: what is broken right now, and why?
- **Certificate audit**: what certificates exist, when do they expire?

Problems come out as a worklist, ordered by what to fix first. Every scan also
saves a shareable HTML report next to where you ran it.

## Run it

Needs Go 1.26+ and make.

```bash
git clone https://github.com/Rusty-Gopher/kupre.git
cd kupre
make tui       # builds and starts the interactive mode
```

Or in two steps: `make build` compiles `./kupre`, then run `./kupre`.

The flow:

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
