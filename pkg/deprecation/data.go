// Package deprecation holds the Kubernetes API deprecation and removal
// database that drives kupre's API checks.
//
// Each entry records a group/version/kind that the API server stops serving in
// a specific release, together with its replacement. The data is derived from
// the upstream deprecated API migration guide:
// https://kubernetes.io/docs/reference/using-api/deprecation-guide/
package deprecation

import (
	"fmt"
	"sort"
	"strings"
)

// APIRemoval records a single API version that is removed in a release.
type APIRemoval struct {
	// Group is the API group, empty for the core group.
	Group string
	// Version is the removed version, e.g. "v1beta1".
	Version string
	// Kind is the resource kind, e.g. "CronJob".
	Kind string
	// Resource is the lowercase plural resource name used in API paths.
	Resource string
	// DeprecatedIn is the release that first deprecated the API, e.g. "1.21".
	DeprecatedIn string
	// RemovedIn is the release that stops serving it, e.g. "1.25".
	RemovedIn string
	// ReplacementGroup and ReplacementVersion name the API to migrate to.
	// An empty ReplacementVersion means the API has no direct successor.
	ReplacementGroup   string
	ReplacementVersion string
	// Notes carries migration caveats beyond a straight apiVersion bump.
	Notes string
}

// GroupVersion renders the removed API's group/version string.
func (r APIRemoval) GroupVersion() string {
	if r.Group == "" {
		return r.Version
	}
	return r.Group + "/" + r.Version
}

// GVK renders the full group/version/kind for display.
func (r APIRemoval) GVK() string { return r.GroupVersion() + " " + r.Kind }

// Replacement renders the successor API, or a note that none exists.
func (r APIRemoval) Replacement() string {
	if r.ReplacementVersion == "" {
		return "no direct replacement"
	}
	if r.ReplacementGroup == "" {
		return r.ReplacementVersion
	}
	return r.ReplacementGroup + "/" + r.ReplacementVersion
}

// removals is the full removal database, ordered by release.
//
// Sources: the upstream deprecated API migration guide and the per-release
// CHANGELOG "Removed APIs" sections. Entries cover 1.25 onward, which is the
// oldest release kupre attempts to reason about.
var removals = []APIRemoval{
	// ---- 1.25 ----
	{Group: "batch", Version: "v1beta1", Kind: "CronJob", Resource: "cronjobs",
		DeprecatedIn: "1.21", RemovedIn: "1.25",
		ReplacementGroup: "batch", ReplacementVersion: "v1"},
	{Group: "discovery.k8s.io", Version: "v1beta1", Kind: "EndpointSlice", Resource: "endpointslices",
		DeprecatedIn: "1.21", RemovedIn: "1.25",
		ReplacementGroup: "discovery.k8s.io", ReplacementVersion: "v1",
		Notes: "the topology field was replaced by deprecatedTopology plus nodeName and zone"},
	{Group: "events.k8s.io", Version: "v1beta1", Kind: "Event", Resource: "events",
		DeprecatedIn: "1.19", RemovedIn: "1.25",
		ReplacementGroup: "events.k8s.io", ReplacementVersion: "v1"},
	{Group: "autoscaling", Version: "v2beta1", Kind: "HorizontalPodAutoscaler", Resource: "horizontalpodautoscalers",
		DeprecatedIn: "1.22", RemovedIn: "1.25",
		ReplacementGroup: "autoscaling", ReplacementVersion: "v2"},
	{Group: "policy", Version: "v1beta1", Kind: "PodDisruptionBudget", Resource: "poddisruptionbudgets",
		DeprecatedIn: "1.21", RemovedIn: "1.25",
		ReplacementGroup: "policy", ReplacementVersion: "v1",
		Notes: "an empty spec.selector in policy/v1 matches every pod in the namespace; in policy/v1beta1 it matched no pods"},
	{Group: "policy", Version: "v1beta1", Kind: "PodSecurityPolicy", Resource: "podsecuritypolicies",
		DeprecatedIn: "1.21", RemovedIn: "1.25",
		Notes: "PSP has no API successor; migrate to Pod Security Admission or a policy engine such as Kyverno or Gatekeeper"},
	{Group: "node.k8s.io", Version: "v1beta1", Kind: "RuntimeClass", Resource: "runtimeclasses",
		DeprecatedIn: "1.22", RemovedIn: "1.25",
		ReplacementGroup: "node.k8s.io", ReplacementVersion: "v1"},

	// ---- 1.26 ----
	{Group: "flowcontrol.apiserver.k8s.io", Version: "v1beta1", Kind: "FlowSchema", Resource: "flowschemas",
		DeprecatedIn: "1.23", RemovedIn: "1.26",
		ReplacementGroup: "flowcontrol.apiserver.k8s.io", ReplacementVersion: "v1beta2"},
	{Group: "flowcontrol.apiserver.k8s.io", Version: "v1beta1", Kind: "PriorityLevelConfiguration", Resource: "prioritylevelconfigurations",
		DeprecatedIn: "1.23", RemovedIn: "1.26",
		ReplacementGroup: "flowcontrol.apiserver.k8s.io", ReplacementVersion: "v1beta2"},
	{Group: "autoscaling", Version: "v2beta2", Kind: "HorizontalPodAutoscaler", Resource: "horizontalpodautoscalers",
		DeprecatedIn: "1.23", RemovedIn: "1.26",
		ReplacementGroup: "autoscaling", ReplacementVersion: "v2"},

	// ---- 1.27 ----
	{Group: "storage.k8s.io", Version: "v1beta1", Kind: "CSIStorageCapacity", Resource: "csistoragecapacities",
		DeprecatedIn: "1.24", RemovedIn: "1.27",
		ReplacementGroup: "storage.k8s.io", ReplacementVersion: "v1"},

	// ---- 1.29 ----
	{Group: "flowcontrol.apiserver.k8s.io", Version: "v1beta2", Kind: "FlowSchema", Resource: "flowschemas",
		DeprecatedIn: "1.26", RemovedIn: "1.29",
		ReplacementGroup: "flowcontrol.apiserver.k8s.io", ReplacementVersion: "v1"},
	{Group: "flowcontrol.apiserver.k8s.io", Version: "v1beta2", Kind: "PriorityLevelConfiguration", Resource: "prioritylevelconfigurations",
		DeprecatedIn: "1.26", RemovedIn: "1.29",
		ReplacementGroup: "flowcontrol.apiserver.k8s.io", ReplacementVersion: "v1"},

	// ---- 1.32 ----
	{Group: "flowcontrol.apiserver.k8s.io", Version: "v1beta3", Kind: "FlowSchema", Resource: "flowschemas",
		DeprecatedIn: "1.29", RemovedIn: "1.32",
		ReplacementGroup: "flowcontrol.apiserver.k8s.io", ReplacementVersion: "v1"},
	{Group: "flowcontrol.apiserver.k8s.io", Version: "v1beta3", Kind: "PriorityLevelConfiguration", Resource: "prioritylevelconfigurations",
		DeprecatedIn: "1.29", RemovedIn: "1.32",
		ReplacementGroup: "flowcontrol.apiserver.k8s.io", ReplacementVersion: "v1"},

	// ---- 1.35 ----
	// Alpha APIs, but this one carries an explicit ACTION REQUIRED: stored
	// v1alpha1 objects must be deleted before the control plane moves to 1.35.
	{Group: "storagemigration.k8s.io", Version: "v1alpha1", Kind: "StorageVersionMigration", Resource: "storageversionmigrations",
		DeprecatedIn: "1.34", RemovedIn: "1.35",
		ReplacementGroup: "storagemigration.k8s.io", ReplacementVersion: "v1beta1",
		Notes: "ACTION REQUIRED: delete all v1alpha1 StorageVersionMigration objects before upgrading"},
	{Group: "storage.k8s.io", Version: "v1alpha1", Kind: "VolumeAttributesClass", Resource: "volumeattributesclasses",
		DeprecatedIn: "1.34", RemovedIn: "1.35",
		ReplacementGroup: "storage.k8s.io", ReplacementVersion: "v1"},

	// ---- 1.36 ----
	{Group: "scheduling.k8s.io", Version: "v1alpha1", Kind: "Workload", Resource: "workloads",
		DeprecatedIn: "1.35", RemovedIn: "1.36",
		ReplacementGroup: "scheduling.k8s.io", ReplacementVersion: "v1alpha2",
		Notes: "replaced by v1alpha2 Workload plus the new PodGroup resource"},

	// ---- 1.37 ----
	// CHANGELOG-1.37 (v1.37.0): "Promoted the core Workload-Aware Scheduling
	// (WAS) API types Workload and PodGroup to scheduling.k8s.io/v1beta1.
	// Remove all v1alpha2 objects from the kube-apiserver before upgrading
	// from v1.36 to v1.37."
	{Group: "scheduling.k8s.io", Version: "v1alpha2", Kind: "Workload", Resource: "workloads",
		DeprecatedIn: "1.37", RemovedIn: "1.37",
		ReplacementGroup: "scheduling.k8s.io", ReplacementVersion: "v1beta1",
		Notes: "ACTION REQUIRED: delete all v1alpha2 objects before upgrading"},
	{Group: "scheduling.k8s.io", Version: "v1alpha2", Kind: "PodGroup", Resource: "podgroups",
		DeprecatedIn: "1.37", RemovedIn: "1.37",
		ReplacementGroup: "scheduling.k8s.io", ReplacementVersion: "v1beta1",
		Notes: "ACTION REQUIRED: delete all v1alpha2 objects before upgrading"},
}

// NOTE ON FORWARD-LOOKING DATA
//
// This table records only removals that have actually shipped. Announced future
// removals are deliberately excluded, because upstream announcements slip: the
// 1.33 changelog stated that resource.k8s.io/v1beta1 would be removed in 1.36,
// and it was not - that version is still served. Encoding announcements as fact
// would make kupre emit confident, wrong upgrade advice, which is worse than
// staying silent. Add an entry here only once the removal has landed in a
// released version.

// All returns the full removal database.
func All() []APIRemoval { return removals }

// RemovedBetween returns every API removed in a release after from and at or
// before to, i.e. the removals that apply to an upgrade across that span.
// Versions are compared as "MAJOR.MINOR" strings parsed into integers.
func RemovedBetween(from, to string) []APIRemoval {
	fMaj, fMin, okF := splitMinor(from)
	tMaj, tMin, okT := splitMinor(to)
	if !okF || !okT {
		return nil
	}

	var out []APIRemoval
	for _, r := range removals {
		rMaj, rMin, ok := splitMinor(r.RemovedIn)
		if !ok {
			continue
		}
		if after(rMaj, rMin, fMaj, fMin) && !after(rMaj, rMin, tMaj, tMin) {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].RemovedIn != out[j].RemovedIn {
			return out[i].RemovedIn < out[j].RemovedIn
		}
		return out[i].GVK() < out[j].GVK()
	})
	return out
}

// ByGroupVersion indexes removals by their group/version string, so a check can
// look up whether a served API version is scheduled for removal.
func ByGroupVersion() map[string][]APIRemoval {
	out := map[string][]APIRemoval{}
	for _, r := range removals {
		out[r.GroupVersion()] = append(out[r.GroupVersion()], r)
	}
	return out
}

// splitMinor parses a "MAJOR.MINOR" or "MAJOR.MINOR.PATCH" string into its
// major and minor components.
func splitMinor(s string) (major, minor int, ok bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	parts := strings.SplitN(s, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	if _, err := fmt.Sscanf(parts[0], "%d", &major); err != nil {
		return 0, 0, false
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &minor); err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

// after reports whether (aMaj, aMin) sorts strictly after (bMaj, bMin).
func after(aMaj, aMin, bMaj, bMin int) bool {
	if aMaj != bMaj {
		return aMaj > bMaj
	}
	return aMin > bMin
}

// DataHorizon is the newest Kubernetes minor release this database has been
// verified against, and the date of that verification.
//
// Everything in this package is a point-in-time snapshot of upstream. Beyond the
// horizon kupre knows nothing - and "I have no data" must never be reported as
// "I checked and found nothing". Checks that consult the database are required
// to call BeyondHorizon and degrade their result accordingly.
//
// When adding data for a new release, bump both of these in the same commit.
const (
	DataHorizon         = "1.37"
	DataHorizonVerified = "2026-10-22"
)

// BeyondHorizon reports whether the given release is newer than the data this
// package carries, meaning any "no findings" answer about it is uninformed.
func BeyondHorizon(minor string) bool {
	hMaj, hMin, okH := splitMinor(DataHorizon)
	vMaj, vMin, okV := splitMinor(minor)
	if !okH || !okV {
		return false
	}
	return after(vMaj, vMin, hMaj, hMin)
}

// HorizonNote renders a reusable explanation for reports.
func HorizonNote(target string) string {
	return fmt.Sprintf(
		"kupre's deprecation database was last verified against Kubernetes %s on %s, "+
			"so it carries no data for %s. Absence of findings here means kupre has "+
			"nothing to check against, not that the release is clean. Review the %s "+
			"changelog manually, and update pkg/deprecation/ to cover it.",
		DataHorizon, DataHorizonVerified, target, target)
}
