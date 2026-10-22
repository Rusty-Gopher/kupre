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
	changelog137 = "https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.37.md"
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

	// ---- 1.37 ----
	// All entries verified 2026-10-22 against the v1.37.0 section of
	// CHANGELOG-1.37; quotes are verbatim from it.
	{
		// Urgent Upgrade Notes: "ACTION REQUIRED: Graduated the SELinuxMount
		// feature gate to GA. The feature is enabled by default in v1.37, which
		// may break existing workloads in clusters with SELinux enabled."
		ReleaseMinor: "1.37",
		ID:           "selinux-mount-ga",
		Title:        "SELinuxMount enabled by default; may break workloads on SELinux nodes",
		Detail: "Volumes are now mounted with the Pod's SELinux label instead of being " +
			"relabelled recursively. Pods sharing a volume with different SELinux labels, or " +
			"privileged and unprivileged Pods sharing a volume, can fail to start. Clusters whose " +
			"nodes do not run SELinux are unaffected.",
		Remediation: "On SELinux-enabled nodes, find affected workloads on the 1.36 cluster first " +
			"(see kubernetes.io/blog/2026/04/22/breaking-changes-in-selinux-volume-labeling/), and " +
			"either fix them or set spec.securityContext.seLinuxChangePolicy: Recursive before upgrading.",
		Detectable: false,
		Docs:       "https://kubernetes.io/blog/2026/04/22/breaking-changes-in-selinux-volume-labeling/",
	},
	{
		// Urgent Upgrade Notes: "ACTION REQUIRED: Fixed eventRecordQPS handling
		// in kubelet configuration to treat 0 as unlimited (no rate limit)".
		ReleaseMinor: "1.37",
		ID:           "kubelet-event-qps-zero-unlimited",
		Title:        "kubelet eventRecordQPS: 0 now means unlimited",
		Detail: "A kubelet configured with eventRecordQPS: 0 previously fell back to the default " +
			"rate limit; from 1.37 it emits events with no rate limit at all, which can flood the " +
			"API server on busy nodes.",
		Remediation: "If any kubelet configuration sets eventRecordQPS: 0, set an explicit non-zero " +
			"value (upstream suggests 50) before upgrading kubelets.",
		Detectable: false,
		Docs:       changelog137,
	},
	{
		// Urgent Upgrade Notes: "Updated the kubelet to log its effective
		// configuration at startup ... restrict the nodes/logs ClusterRole to
		// trusted users."
		ReleaseMinor: "1.37",
		ID:           "kubelet-logs-effective-config",
		Title:        "kubelet logs its effective configuration at startup",
		Detail: "Configuration details now appear in kubelet logs, readable by anyone granted " +
			"nodes/logs.",
		Remediation: "Review which subjects can read nodes/logs and restrict it to trusted users.",
		Detectable:  false,
		Docs:        changelog137,
	},
	{
		// "Deprecated cAdvisor flags are no longer accepted and the kubelet will
		// fail to start if any are set (only --housekeeping-interval is kept)".
		ReleaseMinor: "1.37",
		ID:           "kubelet-cadvisor-flags-removed",
		Title:        "Deprecated cAdvisor kubelet flags removed; kubelet fails to start if set",
		Detail: "The kubelet no longer accepts the legacy cAdvisor flags (--containerd, " +
			"--containerd-namespace, --boot-id-file, --machine-id-file, --storage-driver-*, " +
			"--event-storage-*, --global-housekeeping-interval and others); only " +
			"--housekeeping-interval is kept. cAdvisor application metrics and the " +
			"container_cpu_load_average_10s and container_tasks_state series are no longer exported.",
		Remediation: "Remove these flags from every node's kubelet arguments before upgrading " +
			"kubelets, and update dashboards or alerts using the dropped cAdvisor series.",
		Detectable: false,
		Docs:       changelog137,
	},
	{
		// "Removed the PreventStaticPodAPIReferences feature gate. Static Pods
		// can no longer reference API resources, and this behavior can no
		// longer be disabled."
		ReleaseMinor: "1.37",
		ID:           "static-pod-api-references-prohibited",
		Title:        "Static Pods can no longer reference API objects",
		Detail: "A static Pod manifest that references a Secret, ConfigMap, ServiceAccount " +
			"token or other API object is rejected, and the opt-out gate is gone.",
		Remediation: "Check /etc/kubernetes/manifests (or the kubelet's staticPodPath) on every " +
			"node and replace API references with host files before upgrading.",
		Detectable: false,
		Docs:       changelog137,
	},
	{
		// "kubeadm: Removed the v1beta3 API which was deprecated since v1.31.
		// The v1.35 kubeadm binary can be used to migrate to v1beta4 by using
		// the command kubeadm config migrate."
		ReleaseMinor: "1.37",
		ID:           "kubeadm-v1beta3-removed",
		Title:        "kubeadm v1beta3 configuration API removed",
		Detail: "kubeadm 1.37 rejects kubeadm.k8s.io/v1beta3 configuration files. The " +
			"PublicKeysECDSA kubeadm feature gate was removed with it; use " +
			"ClusterConfiguration.encryptionAlgorithm instead.",
		Remediation: "Migrate any kubeadm config files kept in automation (init/join/upgrade " +
			"configs) to v1beta4 with `kubeadm config migrate` from a 1.35 or 1.36 kubeadm binary.",
		Detectable: false,
		Docs:       changelog137,
	},
	{
		ReleaseMinor: "1.37",
		ID:           "removed-feature-gates-137",
		Title:        "Several feature gates removed; setting them now fails startup",
		Detail: "SidecarContainers, AnyVolumeDataSource, RelaxedDNSSearchValidation, " +
			"GangScheduling, WorkloadAwarePreemption, PreventStaticPodAPIReferences, " +
			"RetryGenerateName, BtreeWatchCache, OrderedNamespaceDeletion, " +
			"StreamingCollectionEncodingToJSON, StreamingCollectionEncodingToProtobuf, " +
			"APIServerTracing, ResilientWatchCacheInitialization and ConsistentListFromCache were " +
			"removed, and the kube-controller-manager --concurrent-service-syncs flag is gone. " +
			"DeclarativeValidationTakeover, DRAPrioritizedList and HostnameOverride are locked.",
		Remediation: "Remove these gates and the removed flag from all component configurations " +
			"before upgrading.",
		Detectable: false,
		Docs:       changelog137,
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
