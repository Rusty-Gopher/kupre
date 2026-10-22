# Security Policy

## Reporting a vulnerability

Report privately via GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository. Please do not open a public issue for a suspected
vulnerability.

Expect an acknowledgement within a week.

## Security model

kupre reads Kubernetes clusters. Two properties are load-bearing:

**It is read-only by construction, not by convention.** The `analyzer.Cluster`
type exposes only narrow Get/List accessors; the underlying typed and dynamic
clients are private and deliberately not exported, so no caller can reach a
mutating verb through the analyzer API. CI additionally greps the tree and
fails on any mutating client call.
`deploy/rbac.yaml` grants only `get` and `list`. A pull request adding
a mutating verb or a write call is a security bug, not a feature.

**It handles credentials.** kupre reads kubeconfig files, which contain cluster
credentials. It never writes to them, never copies them, and never includes
credential material in any output format. Reports contain object names,
namespaces and versions only.

If you find kupre writing to a cluster, modifying a kubeconfig, or emitting
secret material into a report, treat it as a vulnerability and report it.

## Scope

In scope: unintended cluster writes, kubeconfig modification, credential
leakage into output or logs, dependency vulnerabilities in released binaries.

Out of scope: incorrect check results. Those are correctness bugs — file them as
issues. They matter, but they are not security issues.
