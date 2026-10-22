package deprecation

import "time"

// upstreamEOL is the Kubernetes project's end-of-life date per minor release,
// from kubernetes/website data/releases/schedule.yaml and eol.yaml, read
// 2026-10-22. After this date the release gets no patches, security fixes
// included. Managed offerings (EKS extended support, GKE, AKS LTS) may support
// a release longer; that is the provider's promise, not upstream's.
var upstreamEOL = map[string]string{
	"1.26": "2024-02-28",
	"1.27": "2024-07-16",
	"1.28": "2024-10-22",
	"1.29": "2025-02-28",
	"1.30": "2025-07-15",
	"1.31": "2025-11-11",
	"1.32": "2026-02-28",
	"1.33": "2026-06-28",
	"1.34": "2026-10-27",
	"1.35": "2027-02-28",
	"1.36": "2027-06-28",
	"1.37": "2027-10-28",
}

// oldestEOLMinor is the oldest release in upstreamEOL. Anything older is
// certainly past end of life.
const oldestEOLMinor = "1.26"

// EOLDate returns the upstream end-of-life date for a minor release. known is
// false for releases newer than the data; a release older than the data is
// reported with the oldest known date, which it is certainly past.
func EOLDate(minor string) (date time.Time, known bool) {
	if s, ok := upstreamEOL[minor]; ok {
		t, err := time.Parse(time.DateOnly, s)
		return t, err == nil
	}
	oMaj, oMin, okO := splitMinor(oldestEOLMinor)
	vMaj, vMin, okV := splitMinor(minor)
	if okO && okV && after(oMaj, oMin, vMaj, vMin) {
		t, _ := time.Parse(time.DateOnly, upstreamEOL[oldestEOLMinor])
		return t, true
	}
	return time.Time{}, false
}
