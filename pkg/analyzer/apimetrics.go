package analyzer

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// MetricsChecks returns checks built on the API server's own /metrics endpoint.
func MetricsChecks() []Check {
	return []Check{
		{
			Name:        "deprecated-api-requests",
			Description: "Deprecated API endpoints the API server has actually served requests for",
			Category:    CategoryAPI,
			Severity:    SeverityError,
			Action:      ActionPlanAhead,
			Evidence: "Reads the apiserver_requested_deprecated_apis metric from /metrics. The " +
				"API server sets it when a request hits a deprecated endpoint, so a series " +
				"here is proof a client actually made such a request - evidence no object " +
				"scan can produce, and the same signal class EKS/GKE/AKS block upgrades on.",
			Limits: "The metric is in-process state: it covers requests since the current API " +
				"server process started and resets on restart, so absence proves nothing. It " +
				"carries no client identity (deliberately, per KEP-1693) - finding WHO calls " +
				"needs audit logs. On HA control planes kupre sees one member's metrics per " +
				"request. Requires GET on /metrics; skipped without it.",
			Run: checkDeprecatedAPIRequests,
		},
	}
}

// deprecatedAPIUse is one series of apiserver_requested_deprecated_apis.
type deprecatedAPIUse struct {
	Group, Version, Resource, Subresource string
	// RemovedRelease is the minor release that stops serving the endpoint, or
	// "" when the API is deprecated with no removal scheduled.
	RemovedRelease string
}

// GroupVersion renders the group/version of the requested endpoint.
func (u deprecatedAPIUse) GroupVersion() string {
	if u.Group == "" {
		return u.Version
	}
	return u.Group + "/" + u.Version
}

// deprecatedAPIsMetricRe matches one sample line of the metric. Label order is
// not guaranteed by the exposition format, so labels are parsed separately.
var (
	deprecatedAPIsMetricRe = regexp.MustCompile(`^apiserver_requested_deprecated_apis\{([^}]*)\}\s+`)
	metricLabelRe          = regexp.MustCompile(`(\w+)="([^"]*)"`)
)

// parseDeprecatedAPIMetrics extracts every apiserver_requested_deprecated_apis
// series from Prometheus text exposition.
func parseDeprecatedAPIMetrics(raw []byte) []deprecatedAPIUse {
	var out []deprecatedAPIUse
	for _, line := range strings.Split(string(raw), "\n") {
		m := deprecatedAPIsMetricRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		labels := map[string]string{}
		for _, kv := range metricLabelRe.FindAllStringSubmatch(m[1], -1) {
			labels[kv[1]] = kv[2]
		}
		out = append(out, deprecatedAPIUse{
			Group:          labels["group"],
			Version:        labels["version"],
			Resource:       labels["resource"],
			Subresource:    labels["subresource"],
			RemovedRelease: labels["removed_release"],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].GroupVersion() != out[j].GroupVersion() {
			return out[i].GroupVersion() < out[j].GroupVersion()
		}
		return out[i].Resource < out[j].Resource
	})
	return out
}

// checkDeprecatedAPIRequests reports deprecated endpoints that have served
// real requests, split by whether the upgrade path actually removes them.
func checkDeprecatedAPIRequests(ctx context.Context, c *Cluster, up Upgrade) (*Result, error) {
	raw, err := c.RawMetrics(ctx)
	if err != nil {
		return Skip("could not read /metrics (%v) - grant GET on the /metrics nonResourceURL "+
			"(see deploy/rbac.yaml) to enable this evidence", err), nil
	}

	uses := parseDeprecatedAPIMetrics(raw)
	if len(uses) == 0 {
		return Pass("the API server has served no deprecated-API requests since its current " +
			"process started (absence is weak evidence - see limits)"), nil
	}

	var breaking, advisory []AffectedResource
	for _, u := range uses {
		res := AffectedResource{
			Kind:       u.Resource,
			APIVersion: u.GroupVersion(),
			Name:       u.Resource,
		}
		if u.Subresource != "" {
			res.Name = u.Resource + "/" + u.Subresource
		}
		switch {
		case u.RemovedRelease == "":
			res.Detail = "deprecated, no removal scheduled - requests observed"
			advisory = append(advisory, res)
		default:
			removedAt, err := ParseVersion(u.RemovedRelease)
			if err != nil {
				res.Detail = fmt.Sprintf("removal release %q unparseable - requests observed", u.RemovedRelease)
				advisory = append(advisory, res)
				continue
			}
			if up.Crosses(removedAt) {
				res.Detail = fmt.Sprintf("stops being served at %s - requests observed on this cluster",
					u.RemovedRelease)
				breaking = append(breaking, res)
			} else {
				res.Detail = fmt.Sprintf("removal scheduled for %s (after this upgrade) - requests observed",
					u.RemovedRelease)
				advisory = append(advisory, res)
			}
		}
	}

	if len(breaking) > 0 {
		return Fail("%d deprecated API endpoint(s) removed by %s have served real requests",
			len(breaking), up.To.MinorString()).
			WithResources(append(breaking, advisory...)...).
			WithRemediation("Something on this cluster is actively calling APIs that stop " +
				"existing after the upgrade - this is observed traffic, not a guess. The metric " +
				"cannot name the caller; identify it from audit logs (annotation " +
				"k8s.io/deprecated=true) or by checking controllers and CI against the listed " +
				"endpoints, then migrate it before upgrading.").
			WithDocs("https://kubernetes.io/blog/2020/09/03/warnings/"), nil
	}

	return Warn("%d deprecated API endpoint(s) have served requests, none removed by this upgrade",
		len(advisory)).
		WithResources(advisory...).
		WithRemediation("Nothing here breaks at the target version, but these are live callers " +
			"of deprecated endpoints - migration debt that will bite a later upgrade. Worth " +
			"tracking down while the traffic is still observable.").
		WithDocs("https://kubernetes.io/blog/2020/09/03/warnings/"), nil
}
