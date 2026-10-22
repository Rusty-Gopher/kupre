package deprecation

// AddonRelease is one minor release of a cluster add-on with the Kubernetes
// range its vendor publishes support for. Only vendor-published matrices go
// here: an inferred compatibility claim is worse than none.
type AddonRelease struct {
	Minor string // e.g. "1.21"
	// MinKube and MaxKube bound the supported Kubernetes minors, inclusive.
	MinKube, MaxKube string
	// EOL is the end-of-life date (YYYY-MM-DD), or "" while still supported.
	EOL string
}

// CertManagerSource is the vendor's supported-releases page.
const CertManagerSource = "https://cert-manager.io/docs/releases/"

// certManagerReleases is the "Supported Kubernetes" column of cert-manager's
// supported-releases page (cert-manager/website content/docs/releases/
// README.md), read 2026-10-22. 1.22 is announced for ~Nov 2026 with TBD
// support and is deliberately absent.
var certManagerReleases = []AddonRelease{
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
}

// CertManagerRelease looks up a cert-manager minor. known is false for
// releases newer than the data; older than the data means long past EOL.
func CertManagerRelease(minor string) (rel AddonRelease, known, olderThanData bool) {
	for _, r := range certManagerReleases {
		if r.Minor == minor {
			return r, true, false
		}
	}
	oMaj, oMin, _ := splitMinor("1.12")
	vMaj, vMin, ok := splitMinor(minor)
	return AddonRelease{}, false, ok && after(oMaj, oMin, vMaj, vMin)
}

// CertManagerReleaseSupporting returns the newest listed cert-manager minor
// whose support range includes kube, or "" when none does yet.
func CertManagerReleaseSupporting(kube string) string {
	for _, r := range certManagerReleases { // newest first
		if r.EOL == "" && minorWithin(kube, r.MinKube, r.MaxKube) {
			return r.Minor
		}
	}
	return ""
}

// Supports reports whether the release's published range includes kube.
func (r AddonRelease) Supports(kube string) bool { return minorWithin(kube, r.MinKube, r.MaxKube) }

func minorWithin(v, lo, hi string) bool {
	vM, vm, ok1 := splitMinor(v)
	lM, lm, ok2 := splitMinor(lo)
	hM, hm, ok3 := splitMinor(hi)
	if !ok1 || !ok2 || !ok3 {
		return false
	}
	return !after(lM, lm, vM, vm) && !after(vM, vm, hM, hm)
}
