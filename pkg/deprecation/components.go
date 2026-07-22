package deprecation

// This file pins per-release component expectations sourced from kubeadm's
// constants (cmd/kubeadm/app/constants/constants.go on each release branch).
// Like the removal database, it is a verified snapshot: entries exist only for
// releases whose constants were actually read, and consumers must treat an
// absent entry as "unknown", never as "fine".

// ReleaseComponents records the component versions kubeadm pins for one
// Kubernetes minor release.
type ReleaseComponents struct {
	// CoreDNSVersion is kubeadm's pinned CoreDNS image tag, e.g. "v1.14.2".
	CoreDNSVersion string
	// EtcdVersion is kubeadm's default etcd image tag for stacked etcd.
	EtcdVersion string
	// MinExternalEtcdVersion is the minimum external etcd kubeadm accepts.
	MinExternalEtcdVersion string
}

// releaseComponents is keyed by Kubernetes minor ("1.36"). Verified 2026-07-21
// against the release-1.35 and release-1.36 branches of kubernetes/kubernetes.
var releaseComponents = map[string]ReleaseComponents{
	"1.35": {CoreDNSVersion: "v1.13.1", EtcdVersion: "3.6.6-0", MinExternalEtcdVersion: "3.5.21-0"},
	"1.36": {CoreDNSVersion: "v1.14.2", EtcdVersion: "3.6.8-0", MinExternalEtcdVersion: "3.5.24-0"},
}

// ComponentsFor returns kubeadm's pinned component versions for a Kubernetes
// minor release, and whether that release is covered by the snapshot.
func ComponentsFor(minor string) (ReleaseComponents, bool) {
	rc, ok := releaseComponents[minor]
	return rc, ok
}

// RemovedFeatureGate records a feature gate whose removal makes components
// refuse to start when it is still set.
type RemovedFeatureGate struct {
	Name string
	// RemovedIn is the minor release that removed the gate.
	RemovedIn string
}

// removedFeatureGates lists gates removed on the 1.35/1.36 path, from the
// upstream changelogs (see releases.go for the prose entries). Setting any of
// these on a component at or past its RemovedIn release fails startup.
var removedFeatureGates = []RemovedFeatureGate{
	{Name: "StrictCostEnforcementForVAP", RemovedIn: "1.35"},
	{Name: "StrictCostEnforcementForWebhooks", RemovedIn: "1.35"},
	{Name: "SizeMemoryBackedVolumes", RemovedIn: "1.35"},
	{Name: "ComponentSLIs", RemovedIn: "1.35"},
	{Name: "UserNamespacesPodSecurityStandards", RemovedIn: "1.35"},
	{Name: "WatchFromStorageWithoutResourceVersion", RemovedIn: "1.36"},
	{Name: "HonorPVReclaimPolicy", RemovedIn: "1.36"},
}

// FeatureGatesRemovedBetween returns gates removed in a release after from and
// at or before to.
func FeatureGatesRemovedBetween(from, to string) []RemovedFeatureGate {
	fMaj, fMin, okF := splitMinor(from)
	tMaj, tMin, okT := splitMinor(to)
	if !okF || !okT {
		return nil
	}
	var out []RemovedFeatureGate
	for _, g := range removedFeatureGates {
		gMaj, gMin, ok := splitMinor(g.RemovedIn)
		if !ok {
			continue
		}
		if after(gMaj, gMin, fMaj, fMin) && !after(gMaj, gMin, tMaj, tMin) {
			out = append(out, g)
		}
	}
	return out
}
