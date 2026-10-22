package analyzer

import (
	"context"
	"time"

	"github.com/Rusty-Gopher/kupre/pkg/deprecation"
)

// now is the clock lifecycle checks read; tests pin it.
var now = time.Now

// eolSoon is how far ahead an approaching end of life is flagged: roughly one
// upgrade cycle, enough lead time to plan and test the next minor.
const eolSoon = 90 * 24 * time.Hour

// LifecycleChecks report where the cluster and target sit in the upstream
// support window.
func LifecycleChecks() []Check {
	return []Check{
		{
			Name:        "kubernetes-version-support",
			Description: "Kubernetes minor releases past, or close to, upstream end of life",
			Category:    CategoryNode,
			Severity:    SeverityWarning,
			Action:      ActionPlanAhead,
			Evidence: "Compares the API server's minor version, and the upgrade target's, with " +
				"the upstream end-of-life dates published in kubernetes/website release data " +
				"embedded in kupre (no network access at scan time).",
			Limits: "Upstream dates only. EKS extended support, GKE, AKS LTS and other managed " +
				"offerings may patch a release past upstream end of life; check your provider's " +
				"calendar. Node kubelet versions are covered by the skew checks, not here.",
			Run: checkVersionSupport,
		},
	}
}

func checkVersionSupport(_ context.Context, c *Cluster, up Upgrade) (*Result, error) {
	today := now()
	current := c.ServerVersion.MinorString()
	eol, known := deprecation.EOLDate(current)
	if !known {
		return Skip("no upstream end-of-life date for Kubernetes %s in kupre's data "+
			"(newer than the data, verified against 1.37)", current), nil
	}

	// The upgrade mission also evaluates the target: moving onto a release
	// that is already out of support trades one problem for another.
	if target := up.To.MinorString(); target != current {
		if teol, ok := deprecation.EOLDate(target); ok && today.After(teol) {
			return Warn("upgrade target Kubernetes %s reached upstream end of life on %s; "+
				"it no longer receives patches", target, teol.Format(time.DateOnly)).
				WithRemediation("Target a supported minor instead. Upgrades move one minor at a " +
					"time, so plan the path through to a release that is still patched.").
				WithDocs("https://kubernetes.io/releases/"), nil
		}
	}

	switch {
	case today.After(eol):
		return Warn("Kubernetes %s reached upstream end of life on %s (%d days ago); it no "+
			"longer receives patches, security fixes included", current,
			eol.Format(time.DateOnly), int(today.Sub(eol).Hours()/24)).
			WithRemediation("Upgrade to a supported minor. If this is a managed cluster on an " +
				"extended-support plan, confirm the provider's own end-of-support date.").
			WithDocs("https://kubernetes.io/releases/"), nil
	case eol.Sub(today) <= eolSoon:
		return Warn("Kubernetes %s reaches upstream end of life on %s, in %d days", current,
			eol.Format(time.DateOnly), int(eol.Sub(today).Hours()/24)).
			WithRemediation("Schedule the upgrade to the next minor now; after that date no " +
				"further patches ship.").
			WithDocs("https://kubernetes.io/releases/"), nil
	}
	return Pass("Kubernetes %s is supported upstream until %s", current,
		eol.Format(time.DateOnly)), nil
}
