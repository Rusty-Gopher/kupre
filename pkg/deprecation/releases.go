package deprecation

// BreakingChange records a non-API breaking change in a Kubernetes release -
// a removed flag, a disabled volume plugin, a changed default - that a
// preflight scan should surface even though no API version disappears.
//
// Data is drawn from the "Urgent Upgrade Notes" and "ACTION REQUIRED" entries
// of the upstream per-release changelogs.
type BreakingChange struct {
	// ReleaseMinor is the release the change lands in, e.g. "1.35".
	ReleaseMinor string
	// ID is a stable, kebab-case identifier.
	ID string
	// Title is a one-line summary.
	Title string
	// Detail explains the impact.
	Detail string
	// Remediation says what to do about it.
	Remediation string
	// Detectable reports whether kupre can check for this from the
	// Kubernetes API alone. Undetectable entries are surfaced as advisories.
	Detectable bool
	// Docs links to the upstream changelog entry.
	Docs string
}

// changelog CHANGELOG URLs, kept in one place so entries stay short.
const (
	changelog135 = "https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.35.md"
	changelog136 = "https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.36.md"
)

// breakingChanges lists non-API breaking changes by release.
var breakingChanges = []BreakingChange{
	// ---- 1.35 ----
	{
		// CHANGELOG-1.35 Urgent Upgrade Notes, verified 2026-07-22 against the
		// primary source: "ACTION REQUIRED: failCgroupV1 will be set to true
		// from 1.35." An audit pass moved this to 1.36, which would have hidden
		// the warning from every 1.34 -> 1.35 upgrade; see the pinned test.
		ReleaseMinor: "1.35",
		ID:           "cgroup-v1-fails-closed",
		Title:        "kubelet refuses to start on cgroup v1 by default",
		Detail: "The failCgroupV1 kubelet option defaults to true from 1.35, so a node still " +
			"running cgroup v1 will not start its kubelet after the upgrade. cgroup v1 is " +
			"deprecated but not removed; the default flipped to fail-closed.",
		Remediation: "Migrate nodes to cgroup v2 (the default on any modern distro). If that is " +
			"not possible yet, set failCgroupV1: false in the kube-system/kubelet-config ConfigMap " +
			"before upgrading; that buys time, it does not fix the problem.",
		Detectable: false,
		Docs:       changelog135,
	},
	{
		ReleaseMinor: "1.35",
		ID:           "kubelet-pod-infra-container-image-removed",
		Title:        "kubelet --pod-infra-container-image flag removed",
		Detail: "The kubelet no longer accepts --pod-infra-container-image. A kubelet still " +
			"configured with it will fail to start, taking the node down with it. kubeadm writes " +
			"this flag into the kubelet environment file at init time and does not remove it on " +
			"upgrade, so kubeadm-built clusters are the most exposed.",
		Remediation: "Before upgrading kubelets, remove --pod-infra-container-image from the " +
			"kubelet flags on every node (for kubeadm, from nodeRegistration.kubeletExtraArgs and " +
			"/var/lib/kubelet/kubeadm-flags.env).",
		Detectable: false,
		Docs:       changelog135,
	},
	{
		ReleaseMinor: "1.35",
		ID:           "feature-gate-dependencies-validated",
		Title:        "Feature gate dependencies are validated at startup",
		Detail: "Components now fail to start when an enabled feature gate depends on another " +
			"gate that is disabled. In particular AllAlpha=true no longer works on its own.",
		Remediation: "Audit custom feature gate settings on the API server, scheduler, controller " +
			"manager, and kubelet before upgrading.",
		Detectable: false,
		Docs:       changelog135,
	},
	{
		ReleaseMinor: "1.35",
		ID:           "removed-feature-gates-135",
		Title:        "Several feature gates removed; setting them now fails startup",
		Detail: "StrictCostEnforcementForVAP, StrictCostEnforcementForWebhooks, " +
			"SizeMemoryBackedVolumes, ComponentSLIs, and UserNamespacesPodSecurityStandards were " +
			"removed. A component still passing them will refuse to start.",
		Remediation: "Remove these gates from all component configurations before upgrading.",
		Detectable:  false,
		Docs:        changelog135,
	},
	{
		ReleaseMinor: "1.35",
		ID:           "kube-proxy-ipvs-deprecated",
		Title:        "kube-proxy ipvs mode deprecated",
		Detail:       "The ipvs proxy mode is deprecated in favour of nftables. It still works, but is now on a removal path.",
		Remediation:  "Plan a migration of kube-proxy to nftables mode.",
		Detectable:   true,
		Docs:         changelog135,
	},
	{
		ReleaseMinor: "1.35",
		ID:           "kubectl-exec-separator-required",
		Title:        "kubectl exec requires the -- separator",
		Detail: "`kubectl exec POD COMMAND` without `--` is no longer supported. Scripts and CI " +
			"jobs using the old form will break.",
		Remediation: "Update scripts to `kubectl exec POD -- COMMAND`.",
		Detectable:  false,
		Docs:        changelog135,
	},

	// ---- 1.36 ----
	{
		ReleaseMinor: "1.36",
		ID:           "gitrepo-volume-disabled",
		Title:        "gitRepo volume plugin disabled with no way to re-enable it",
		Detail: "The gitRepo volume type is disabled by default and, unlike previous " +
			"deprecations, there is no feature gate to turn it back on. Pods using a gitRepo " +
			"volume will fail to start.",
		Remediation: "Replace gitRepo volumes with an init container that clones into an " +
			"emptyDir, or bake the content into the image.",
		Detectable: true,
		Docs:       changelog136,
	},
	{
		ReleaseMinor: "1.36",
		ID:           "portworx-intree-removed",
		Title:        "In-tree Portworx volume plugin removed",
		Detail: "The in-tree Portworx plugin is gone and CSI migration is complete. The " +
			"CSIMigrationPortworx and InTreePluginPortworxUnregister gates were removed with it.",
		Remediation: "Ensure the pxd.portworx.com CSI driver is installed and all Portworx " +
			"volumes have been migrated to it.",
		Detectable: true,
		Docs:       changelog136,
	},
	{
		ReleaseMinor: "1.36",
		ID:           "kubeadm-flexvolume-removed",
		Title:        "kubeadm support for flex-volume removed",
		Detail: "kubeadm no longer configures the flex-volume plugin directory. Clusters still " +
			"relying on FlexVolume need a custom non-distroless controller-manager image plus " +
			"explicit --flex-volume-plugin-dir and extraVolumes configuration.",
		Remediation: "Migrate FlexVolume drivers to CSI. If you must keep FlexVolume, apply the " +
			"custom kubeadm configuration before upgrading, not after.",
		Detectable: true,
		Docs:       changelog136,
	},
	{
		ReleaseMinor: "1.36",
		ID:           "dra-rbac-tightened",
		Title:        "DRA drivers need new RBAC permissions",
		Detail: "With DRAResourceClaimGranularStatusAuthorization, Dynamic Resource Allocation " +
			"drivers and controllers require new resourceclaims/binding and resourceclaims/driver " +
			"permissions.",
		Remediation: "Update the ClusterRoles of any DRA driver before upgrading.",
		Detectable:  false,
		Docs:        changelog136,
	},
	{
		ReleaseMinor: "1.36",
		ID:           "metric-renames-136",
		Title:        "Metrics renamed: volume_operation_total_errors and etcd_bookmark_counts",
		Detail: "volume_operation_total_errors became volume_operation_errors_total, and " +
			"etcd_bookmark_counts became etcd_bookmark_total. Dashboards and alert rules " +
			"referencing the old names will silently stop matching.",
		Remediation: "Update Prometheus alert rules and Grafana dashboards to the new metric names.",
		Detectable:  false,
		Docs:        changelog136,
	},
	{
		ReleaseMinor: "1.36",
		ID:           "externalips-deprecated",
		Title:        "Service .spec.externalIPs deprecated",
		Detail:       "Services using spec.externalIPs now emit a deprecation warning.",
		Remediation:  "Plan a migration to LoadBalancer or Ingress for these Services.",
		Detectable:   true,
		Docs:         changelog136,
	},
}

// BreakingChangesBetween returns the non-API breaking changes landing in a
// release after from and at or before to.
func BreakingChangesBetween(from, to string) []BreakingChange {
	fMaj, fMin, okF := splitMinor(from)
	tMaj, tMin, okT := splitMinor(to)
	if !okF || !okT {
		return nil
	}

	var out []BreakingChange
	for _, bc := range breakingChanges {
		bMaj, bMin, ok := splitMinor(bc.ReleaseMinor)
		if !ok {
			continue
		}
		if after(bMaj, bMin, fMaj, fMin) && !after(bMaj, bMin, tMaj, tMin) {
			out = append(out, bc)
		}
	}
	return out
}

// BreakingChangeByID looks up a single entry.
func BreakingChangeByID(id string) (BreakingChange, bool) {
	for _, bc := range breakingChanges {
		if bc.ID == id {
			return bc, true
		}
	}
	return BreakingChange{}, false
}
