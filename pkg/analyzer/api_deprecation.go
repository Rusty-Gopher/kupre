package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Rusty-Gopher/kupre/pkg/deprecation"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// APIChecks returns checks for removed and deprecated Kubernetes APIs.
func APIChecks() []Check {
	return []Check{
		{
			Name:        "api-removals-on-path",
			Description: "API versions this cluster serves that the target release stops serving",
			Category:    CategoryAPI,
			Severity:    SeverityWarning,
			Action:      ActionPlanAhead,
			Evidence:    "API discovery on the live cluster, compared against the removal database.",
			Limits: "Says nothing about whether anything uses these APIs. A cluster on the " +
				"source version is expected to serve everything the target removes - that is " +
				"the normal state, not a defect. Use kubent or Pluto against your manifests, " +
				"Helm releases and CI to find actual usage.",
			Run: checkAPIRemovalsOnPath,
		},
		{
			Name:        "removed-api-objects",
			Description: "Objects readable through an API version the target release removes",
			Category:    CategoryAPI,
			Severity:    SeverityWarning,
			Action:      ActionPlanAhead,
			Evidence: "Lists objects through the deprecated endpoint, and reads each object's " +
				"last-applied-configuration annotation where present to see which apiVersion " +
				"was actually applied.",
			Limits: "The API server converts objects to whichever version is requested, so " +
				"listing through an old endpoint does NOT prove anything was authored or " +
				"stored that way. Only objects with a matching last-applied-configuration are " +
				"confirmed. Objects without that annotation are reported as unknown, not as " +
				"deprecated usage.",
			Run: checkRemovedAPIObjects,
		},
		{
			Name:        "crd-deprecated-versions",
			Description: "CustomResourceDefinitions serving versions marked deprecated",
			Category:    CategoryAPI,
			Severity:    SeverityWarning,
			Action:      ActionReviewLater,
			Run:         checkCRDDeprecatedVersions,
		},
		{
			Name:        "upgrade-path-sane",
			Description: "The requested upgrade follows a supported one-minor-version path",
			Category:    CategoryAPI,
			Severity:    SeverityError,
			Action:      ActionFixBeforeStart,
			Run:         checkUpgradePath,
		},
	}
}

// checkUpgradePath validates the requested version transition itself. Skipping
// minor versions is unsupported by Kubernetes and by every managed platform.
func checkUpgradePath(_ context.Context, c *Cluster, up Upgrade) (*Result, error) {
	switch {
	case up.To.Compare(up.From) == 0:
		return Skip("target %s matches the current server version; nothing to upgrade", up.To.String()), nil

	case up.To.LessThan(up.From):
		return Fail("target %s is older than the current server version %s",
			up.To.String(), up.From.String()).
			WithRemediation("Kubernetes does not support downgrading the control plane. " +
				"Restore from a backup taken before the original upgrade instead."), nil

	case up.To.Major != up.From.Major:
		return Fail("target %s crosses a major version boundary from %s",
			up.To.String(), up.From.String()).
			WithRemediation("Major version transitions are not a supported in-place upgrade path."), nil

	case up.Skew() > 1:
		return Fail("target %s is %d minor versions ahead of %s",
			up.To.MinorString(), up.Skew(), up.From.MinorString()).
			WithRemediation(
				"Kubernetes supports upgrading one minor version at a time. Upgrade through "+
					"each intermediate release in turn: %s. kupre has evaluated the full span, "+
					"so the findings below cover every release on that path.",
				strings.Join(minorList(up.Path()), " → ")).
			WithDocs("https://kubernetes.io/releases/version-skew-policy/"), nil

	default:
		return Pass("%s → %s is a supported single-minor upgrade",
			up.From.MinorString(), up.To.MinorString()), nil
	}
}

// beyondHorizon builds the result used when the upgrade target is newer than
// the deprecation database. Reporting Pass here would be the tool's single most
// dangerous output: an uninformed answer that reads as a clean bill of health.
func beyondHorizon(up Upgrade) (*Result, error) {
	return Warn("no deprecation data for Kubernetes %s - this check could not draw a conclusion",
		up.To.MinorString()).
		WithRemediation("%s", deprecation.HorizonNote(up.To.MinorString())).
		WithDocs("https://kubernetes.io/docs/reference/using-api/deprecation-guide/"), nil
}

// discoveryResources renders failed discovery groups as findings resources.
func discoveryResources(groups []string) []AffectedResource {
	out := make([]AffectedResource, 0, len(groups))
	for _, gv := range groups {
		out = append(out, AffectedResource{
			Kind: "APIGroup", Name: gv,
			Detail: "discovery failed; contents unknown",
		})
	}
	return out
}

// minorList renders versions as their minor strings.
func minorList(vs []Version) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.MinorString())
	}
	return out
}

// checkAPIRemovalsOnPath reports which API versions the cluster currently serves
// that the target release stops serving.
//
// This is an availability change, not a defect. A cluster running the source
// version is *expected* to serve every API the target removes - that is what
// "removed in the next release" means. An earlier version of this check treated
// it as a blocking error, which would have failed every legitimate upgrade
// crossing any removal.
//
// Serving an API is also not evidence that anything uses it. Establishing usage
// requires the original manifests (Helm releases, last-applied annotations, CI
// repositories) or API server audit metrics, none of which are visible from a
// read-only object scan. The result says so explicitly.
func checkAPIRemovalsOnPath(ctx context.Context, c *Cluster, up Upgrade) (*Result, error) {
	served, err := c.ServedResources(ctx)
	if err != nil {
		return nil, err
	}
	if len(served) == 0 {
		return nil, fmt.Errorf("discovery returned no API resources")
	}
	discoveryFailures, err := c.DiscoveryFailures(ctx)
	if err != nil {
		return nil, err
	}

	scheduled := deprecation.RemovedBetween(up.From.MinorString(), up.To.MinorString())
	if len(scheduled) == 0 {
		if deprecation.BeyondHorizon(up.To.MinorString()) {
			return beyondHorizon(up)
		}
		return Pass("no API removals scheduled between %s and %s",
			up.From.MinorString(), up.To.MinorString()), nil
	}

	var hits []AffectedResource
	for _, r := range scheduled {
		gvr := schema.GroupVersionResource{Group: r.Group, Version: r.Version, Resource: r.Resource}
		ok, err := c.Serves(ctx, gvr)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		detail := fmt.Sprintf("removed in %s → use %s", r.RemovedIn, r.Replacement())
		if r.Notes != "" {
			detail += "; " + r.Notes
		}
		hits = append(hits, AffectedResource{
			Kind: r.Kind, APIVersion: r.GroupVersion(), Name: r.Resource, Detail: detail,
		})
	}

	if len(hits) == 0 {
		if deprecation.BeyondHorizon(up.To.MinorString()) {
			return beyondHorizon(up)
		}
		if len(discoveryFailures) > 0 {
			return Warn("no removed API versions found, but discovery failed for %d group(s); "+
				"those groups are unverified", len(discoveryFailures)).
				WithResources(discoveryResources(discoveryFailures)...).
				WithRemediation("The API server could not enumerate these groups (usually a down " +
					"aggregated API). Anything in them is invisible to this check, so this result " +
					"is not a clean verdict. Restore the failing group or re-run once discovery " +
					"recovers."), nil
		}
		return Pass("cluster serves none of the %d API version(s) removed between %s and %s",
			len(scheduled), up.From.MinorString(), up.To.MinorString()), nil
	}
	sortResources(hits)
	return Warn("%d API version(s) this cluster serves stop being served at %s",
		len(hits), up.To.MinorString()).
		WithResources(hits...).
		WithRemediation("kupre cannot tell from the cluster whether anything still uses these "+
			"versions - a cluster on %s is expected to serve them. Establish usage from the "+
			"sources kupre cannot see: run kubent or Pluto over your Helm releases, manifest "+
			"repositories and CI pipelines, and check the apiserver_requested_deprecated_apis "+
			"metric if you scrape it. Migrate whatever you find before upgrading.",
			up.From.MinorString()).
		WithCommands(
			"kubectl get --raw /metrics | grep apiserver_requested_deprecated_apis",
		).
		WithDocs("https://kubernetes.io/docs/reference/using-api/deprecation-guide/"), nil
}

// lastAppliedAnnotation holds the manifest kubectl apply last sent, including
// the apiVersion the operator actually wrote.
const lastAppliedAnnotation = "kubectl.kubernetes.io/last-applied-configuration"

// checkRemovedAPIObjects reports objects readable through an API version the
// upgrade removes, separating what is confirmed from what is merely possible.
//
// The subtlety that makes the naive version of this check wrong: the API server
// converts objects to whichever version the client requests. Listing CronJobs
// through batch/v1beta1 returns every CronJob in the cluster, including ones
// authored as batch/v1. So the list alone proves nothing about how anything was
// written - it only proves the old endpoint still answers.
//
// The one piece of authorship evidence visible from the cluster is the
// last-applied-configuration annotation, which records the apiVersion kubectl
// actually sent. Where it matches the deprecated version, usage is confirmed.
// Where it is absent - Helm, operators, and server-side apply do not write it -
// nothing can be concluded, and the object is reported as unknown rather than
// counted as deprecated usage.
func checkRemovedAPIObjects(ctx context.Context, c *Cluster, up Upgrade) (*Result, error) {
	scheduled := deprecation.RemovedBetween(up.From.MinorString(), up.To.MinorString())
	if len(scheduled) == 0 {
		if deprecation.BeyondHorizon(up.To.MinorString()) {
			return beyondHorizon(up)
		}
		return Pass("no API removals scheduled between %s and %s",
			up.From.MinorString(), up.To.MinorString()), nil
	}

	var confirmed, unknown []AffectedResource
	var unreadable []string
	for _, r := range scheduled {
		gvr := schema.GroupVersionResource{Group: r.Group, Version: r.Version, Resource: r.Resource}
		ok, err := c.Serves(ctx, gvr)
		if err != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s (%v)", gvr.String(), err))
			continue
		}
		if !ok {
			continue
		}
		objs, err := c.ListGVR(ctx, gvr)
		if err != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s (%v)", gvr.String(), err))
			continue
		}
		for _, o := range objs {
			res := AffectedResource{
				Kind:       r.Kind,
				APIVersion: r.GroupVersion(),
				Namespace:  o.GetNamespace(),
				Name:       o.GetName(),
			}
			applied, known := appliedAPIVersion(o.GetAnnotations())
			switch {
			case known && applied == r.GroupVersion():
				res.Detail = fmt.Sprintf(
					"last applied as %s - confirmed; migrate to %s", applied, r.Replacement())
				confirmed = append(confirmed, res)
			case known:
				// Applied under a different version, so this object is already
				// on a supported apiVersion and needs nothing.
				continue
			default:
				res.Detail = fmt.Sprintf(
					"readable via %s, but no last-applied annotation - authored version unknown",
					r.GroupVersion())
				unknown = append(unknown, res)
			}
		}
	}

	if len(confirmed) == 0 && len(unknown) == 0 {
		if len(unreadable) > 0 {
			sort.Strings(unreadable)
			return Skip("could not inspect %d API resource(s) removed by %s: %s",
				len(unreadable), up.To.MinorString(), strings.Join(unreadable, "; ")), nil
		}
		if deprecation.BeyondHorizon(up.To.MinorString()) {
			return beyondHorizon(up)
		}
		return Pass("no objects readable through an API version removed by %s",
			up.To.MinorString()), nil
	}

	sortResources(confirmed)
	sortResources(unknown)

	if len(confirmed) > 0 {
		return Fail("%d object(s) were applied using an API version removed by %s%s",
			len(confirmed), up.To.MinorString(), unreadableSummary(unreadable)).
			WithResources(append(confirmed, unknown...)...).
			WithRemediation("The confirmed objects carry a last-applied-configuration naming a "+
				"version that disappears at %s; re-apply them under the replacement apiVersion. "+
				"Any objects listed as \"authored version unknown\" could not be established "+
				"either way - the API server converts on read, so their presence here is not "+
				"evidence of deprecated usage. Check those against your manifests.",
				up.To.MinorString()).
			WithDocs("https://kubernetes.io/docs/reference/using-api/deprecation-guide/"), nil
	}

	return Warn("%d object(s) are readable through a removed API version, authorship unknown%s",
		len(unknown), unreadableSummary(unreadable)).
		WithResources(unknown...).
		WithRemediation("None of these carry a last-applied-configuration annotation, so kupre "+
			"cannot tell which apiVersion they were written with - Helm, operators and "+
			"server-side apply do not set it, and the API server converts objects on read. "+
			"This is not evidence of deprecated usage. Confirm against your manifests with "+
			"kubent or Pluto before %s.", up.To.MinorString()).
		WithDocs("https://kubernetes.io/docs/reference/using-api/deprecation-guide/"), nil
}

func unreadableSummary(unreadable []string) string {
	if len(unreadable) == 0 {
		return ""
	}
	return fmt.Sprintf("; %d additional API resource(s) could not be inspected", len(unreadable))
}

// appliedAPIVersion extracts the apiVersion from a last-applied-configuration
// annotation. The second return reports whether the annotation was usable.
func appliedAPIVersion(annotations map[string]string) (string, bool) {
	raw, ok := annotations[lastAppliedAnnotation]
	if !ok || raw == "" {
		return "", false
	}
	var manifest struct {
		APIVersion string `json:"apiVersion"`
	}
	if err := json.Unmarshal([]byte(raw), &manifest); err != nil || manifest.APIVersion == "" {
		return "", false
	}
	return manifest.APIVersion, true
}

// checkCRDDeprecatedVersions finds CRDs that still serve a version their own
// definition marks deprecated, and CRDs serving beta versions alongside stable
// ones. Both are migration debt that surfaces during upgrades.
func checkCRDDeprecatedVersions(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	crds, err := c.CustomResourceDefinitions(ctx)
	if err != nil {
		return nil, err
	}
	if len(crds) == 0 {
		return Skip("no CustomResourceDefinitions found"), nil
	}

	var issues []AffectedResource
	for _, crd := range crds {
		var served, deprecated, betas []string
		hasStable := false
		for _, v := range crd.Spec.Versions {
			if !v.Served {
				continue
			}
			served = append(served, v.Name)
			if v.Deprecated {
				deprecated = append(deprecated, v.Name)
			}
			switch {
			case strings.Contains(v.Name, "beta"), strings.Contains(v.Name, "alpha"):
				betas = append(betas, v.Name)
			default:
				hasStable = true
			}
		}

		switch {
		case len(deprecated) > 0:
			issues = append(issues, AffectedResource{
				Kind: "CustomResourceDefinition", APIVersion: "apiextensions.k8s.io/v1",
				Name:   crd.Name,
				Detail: fmt.Sprintf("serves deprecated version(s) %s", strings.Join(deprecated, ", ")),
			})
		case hasStable && len(betas) > 0:
			issues = append(issues, AffectedResource{
				Kind: "CustomResourceDefinition", APIVersion: "apiextensions.k8s.io/v1",
				Name: crd.Name,
				Detail: fmt.Sprintf("still serves pre-release version(s) %s alongside stable %s",
					strings.Join(betas, ", "), strings.Join(stableOnly(served), ", ")),
			})
		}
	}

	if len(issues) == 0 {
		return Pass("none of %d CustomResourceDefinition(s) serve deprecated versions", len(crds)), nil
	}
	sortResources(issues)
	return Warn("%d of %d CustomResourceDefinition(s) serve deprecated or superseded versions",
		len(issues), len(crds)).
		WithResources(issues...).
		WithRemediation("These are not blocked by the Kubernetes upgrade itself, but the operators " +
			"that own them typically drop old versions in the releases you will need for the new " +
			"Kubernetes version. Migrate stored objects to the stable version and stop serving the " +
			"old one - check each CRD's status.storedVersions before removing it."), nil
}

// stableOnly filters a version list down to non-alpha, non-beta entries.
func stableOnly(vs []string) []string {
	var out []string
	for _, v := range vs {
		if !strings.Contains(v, "beta") && !strings.Contains(v, "alpha") {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
