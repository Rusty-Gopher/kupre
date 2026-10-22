package deprecation

import (
	"strings"
	"time"
)

// Add-on support data. Only vendor-published matrices go here: an inferred
// compatibility claim is worse than none.

// Addon describes one add-on and the vendor's published Kubernetes matrix.
type Addon struct {
	// Name is how reports refer to the add-on.
	Name string
	// Image is the final path segments of the image that identifies the
	// add-on and carries its version tag, e.g. "jetstack/cert-manager-controller".
	Image string
	// Source is the vendor page the data comes from.
	Source string
	// Claim is the vendor's own word for the range: "supports" or "is tested
	// against". Reports use it so kupre never overstates the vendor.
	Claim string
	// Releases is newest first.
	Releases []AddonRelease
	// OlderUnmaintained is true when the vendor's policy makes anything older
	// than the listed releases unmaintained. Without it kupre only says the
	// version predates its data.
	OlderUnmaintained bool
}

// AddonRelease is one minor release with the Kubernetes range the vendor
// publishes for it.
type AddonRelease struct {
	Minor string
	// MinKube and MaxKube bound the published Kubernetes minors, inclusive.
	MinKube, MaxKube string
	// EOL is the end-of-life date (YYYY-MM-DD) when the vendor publishes
	// one; Unmaintained marks a release dropped from the maintained list
	// without a published date.
	EOL          string
	Unmaintained bool
}

// Addons lists every add-on kupre knows a published matrix for.
var Addons = []Addon{
	{
		// cert-manager/website content/docs/releases/README.md, read
		// 2026-10-22. 1.22 (~Nov 2026, support TBD) is deliberately absent.
		Name:   "cert-manager",
		Image:  "cert-manager-controller",
		Source: "https://cert-manager.io/docs/releases/",
		Claim:  "supports",
		// "All cert-manager releases are supported at least until the
		// release of a second subsequent version."
		OlderUnmaintained: true,
		Releases: []AddonRelease{
			{Minor: "1.21", MinKube: "1.33", MaxKube: "1.36"},
			{Minor: "1.20", MinKube: "1.32", MaxKube: "1.35"},
			{Minor: "1.19", MinKube: "1.31", MaxKube: "1.35", EOL: "2026-07-08"},
			{Minor: "1.18", MinKube: "1.29", MaxKube: "1.33", EOL: "2026-03-10"},
			{Minor: "1.17", MinKube: "1.29", MaxKube: "1.33", EOL: "2025-10-07"},
			{Minor: "1.16", MinKube: "1.25", MaxKube: "1.32", EOL: "2025-06-10"},
			{Minor: "1.15", MinKube: "1.25", MaxKube: "1.32", EOL: "2025-02-03"},
			{Minor: "1.14", MinKube: "1.24", MaxKube: "1.31", EOL: "2024-10-03"},
			{Minor: "1.13", MinKube: "1.21", MaxKube: "1.27", EOL: "2024-06-05"},
			{Minor: "1.12", MinKube: "1.22", MaxKube: "1.32", EOL: "2025-05-19"},
		},
	},
	{
		// Documentation/network/kubernetes/compatibility.rst on each
		// cilium/cilium release branch, and the maintained "Stable Releases"
		// in its README.rst (v1.18-v1.20), read 2026-10-22. Cilium's wording:
		// listed versions are "e2e tested and guaranteed to be compatible";
		// others "depend on the forward / backward compatibility" of
		// Kubernetes. So outside the list is untested, not unsupported.
		Name:   "Cilium",
		Image:  "cilium/cilium",
		Source: "https://docs.cilium.io/en/stable/network/kubernetes/compatibility/",
		Claim:  "is e2e tested against",
		// Older branches are absent from the maintained stable releases.
		OlderUnmaintained: true,
		Releases: []AddonRelease{
			{Minor: "1.20", MinKube: "1.33", MaxKube: "1.36"},
			{Minor: "1.19", MinKube: "1.32", MaxKube: "1.35"},
			{Minor: "1.18", MinKube: "1.30", MaxKube: "1.33"},
			{Minor: "1.17", MinKube: "1.29", MaxKube: "1.32", Unmaintained: true},
			{Minor: "1.16", MinKube: "1.27", MaxKube: "1.30", Unmaintained: true},
		},
	},
	{
		// tigera/docs calico_versioned_docs/version-3.3x/_includes/partials/
		// _system-requirements.mdx, "Supported versions", read 2026-10-22:
		// "We test Calico <version> against the following Kubernetes
		// versions. Other versions may work, but we are not actively testing
		// them." Only 3.31-3.33 have versioned docs; no EOL policy is
		// published there, so nothing is marked unmaintained.
		Name:   "Calico",
		Image:  "calico/node",
		Source: "https://docs.tigera.io/calico/latest/getting-started/kubernetes/requirements",
		Claim:  "is tested against",
		Releases: []AddonRelease{
			{Minor: "3.33", MinKube: "1.35", MaxKube: "1.37"},
			{Minor: "3.32", MinKube: "1.34", MaxKube: "1.36"},
			{Minor: "3.31", MinKube: "1.32", MaxKube: "1.35"},
		},
	},
	{
		// envoyproxy/gateway site/content/en/news/releases/matrix.md, read
		// 2026-10-22: "Supported version combinations are listed below", with
		// an End of Life date per release. Common ingress-nginx migration
		// target. The "latest" (dev) row is deliberately absent.
		Name:              "Envoy Gateway",
		Image:             "envoyproxy/gateway",
		Source:            "https://gateway.envoyproxy.io/news/releases/matrix/",
		Claim:             "supports",
		OlderUnmaintained: true,
		Releases: []AddonRelease{
			{Minor: "1.9", MinKube: "1.33", MaxKube: "1.36", EOL: "2027-02-14"},
			{Minor: "1.8", MinKube: "1.32", MaxKube: "1.35", EOL: "2026-11-08"},
			{Minor: "1.7", MinKube: "1.32", MaxKube: "1.35", EOL: "2026-08-05"},
			{Minor: "1.6", MinKube: "1.30", MaxKube: "1.33", EOL: "2026-05-13"},
			{Minor: "1.5", MinKube: "1.30", MaxKube: "1.33", EOL: "2026-02-13"},
			{Minor: "1.4", MinKube: "1.30", MaxKube: "1.33", EOL: "2025-11-13"},
			{Minor: "1.3", MinKube: "1.29", MaxKube: "1.32", EOL: "2025-07-30"},
			{Minor: "1.2", MinKube: "1.28", MaxKube: "1.31", EOL: "2025-05-06"},
			{Minor: "1.1", MinKube: "1.27", MaxKube: "1.30", EOL: "2025-01-22"},
			{Minor: "1.0", MinKube: "1.26", MaxKube: "1.29", EOL: "2024-09-13"},
		},
	},
}

// CheckName is the check identifier for an add-on, e.g. "envoy-gateway-compatibility".
func (a Addon) CheckName() string {
	return strings.ReplaceAll(strings.ToLower(a.Name), " ", "-") + "-compatibility"
}

// Release looks up a minor. known is false for releases outside the data;
// olderThanData then says whether it predates every listed release.
func (a Addon) Release(minor string) (rel AddonRelease, known, olderThanData bool) {
	for _, r := range a.Releases {
		if r.Minor == minor {
			return r, true, false
		}
	}
	oldest := a.Releases[len(a.Releases)-1].Minor
	oMaj, oMin, _ := splitMinor(oldest)
	vMaj, vMin, ok := splitMinor(minor)
	return AddonRelease{}, false, ok && after(oMaj, oMin, vMaj, vMin)
}

// NewestCovering returns the newest release maintained on today whose
// published range includes kube, or "" when none does yet.
func (a Addon) NewestCovering(kube string, today time.Time) string {
	for _, r := range a.Releases {
		if r.Maintained(today) && r.Covers(kube) {
			return r.Minor
		}
	}
	return ""
}

// Maintained reports whether the release is still maintained on today: not
// marked unmaintained, and its published end of life, if any, not yet reached.
func (r AddonRelease) Maintained(today time.Time) bool {
	if r.Unmaintained {
		return false
	}
	if r.EOL == "" {
		return true
	}
	t, err := time.Parse(time.DateOnly, r.EOL)
	return err == nil && t.After(today)
}

// Covers reports whether the release's published range includes kube.
func (r AddonRelease) Covers(kube string) bool { return minorWithin(kube, r.MinKube, r.MaxKube) }

func minorWithin(v, lo, hi string) bool {
	vM, vm, ok1 := splitMinor(v)
	lM, lm, ok2 := splitMinor(lo)
	hM, hm, ok3 := splitMinor(hi)
	if !ok1 || !ok2 || !ok3 {
		return false
	}
	return !after(lM, lm, vM, vm) && !after(vM, vm, hM, hm)
}
