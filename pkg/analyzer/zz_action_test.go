package analyzer

import "testing"

// TestEveryCheckDeclaresAction guards against a new check silently defaulting
// to ActionReviewLater and being filed under "not blocking this upgrade", which
// is where a real finding goes to be ignored.
func TestEveryCheckDeclaresAction(t *testing.T) {
	// Checks that are genuinely "review later" - reviewed and confirmed.
	intentional := map[string]bool{
		"crd-deprecated-versions":  true,
		"single-replica-workloads": true,
		"webhook-failure-policy":   true,
		"webhook-scope":            true,
		"webhook-timeout":          true,
		"service-external-ips":     true,
		"legacy-endpoints":         true,
	}
	for _, c := range AllChecks() {
		if c.Action == ActionReviewLater && !intentional[c.Name] {
			t.Errorf("check %q has no Action set - it will be filed under "+
				"%q. Set one explicitly, or add it to the intentional list here.",
				c.Name, BucketReviewLater.Title())
		}
	}
}
