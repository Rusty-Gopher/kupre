package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/Rusty-Gopher/kupre/pkg/deprecation"
)

// AddonChecks compare installed cluster add-ons with the Kubernetes versions
// their vendors publish support for.
func AddonChecks() []Check {
	return []Check{
		{
			Name:        "cert-manager-compatibility",
			Description: "cert-manager version supported on the cluster and target Kubernetes versions",
			Category:    CategoryWorkload,
			Severity:    SeverityWarning,
			Action:      ActionPlanAhead,
			Evidence: "Reads the cert-manager controller version from its Deployment's image tag " +
				"and compares it with the support matrix cert-manager publishes, embedded in kupre.",
			Limits: "Outside the published range means unsupported, not necessarily broken. A " +
				"digest-only or re-tagged image cannot be versioned. Vendor LTS builds (for " +
				"example Palo Alto Networks' 1.17 LTS) have their own support dates.",
			Run: checkCertManagerCompat,
		},
	}
}

// certManagerVersion finds the cert-manager controller and its version, from
// the image tag of a container whose image is cert-manager-controller.
func certManagerVersion(ctx context.Context, c *Cluster) (AffectedResource, Version, bool, error) {
	deploys, err := c.Deployments(ctx)
	if err != nil {
		return AffectedResource{}, Version{}, false, err
	}
	for _, d := range deploys {
		for _, ctr := range d.Spec.Template.Spec.Containers {
			// A digest pins content but carries no version; drop it, then
			// read the version from the tag if there is one.
			ref, _, _ := strings.Cut(ctr.Image, "@")
			repo, tag := splitImageTag(ref)
			if !strings.HasSuffix(repo, "/cert-manager-controller") && repo != "cert-manager-controller" {
				continue
			}
			res := AffectedResource{Kind: "Deployment", APIVersion: "apps/v1",
				Namespace: d.Namespace, Name: d.Name, Detail: "image " + ctr.Image}
			v, perr := ParseVersion(tag)
			return res, v, perr == nil, nil
		}
	}
	return AffectedResource{}, Version{}, false, nil
}

// splitImageTag splits "repo:tag", leaving a registry port alone.
func splitImageTag(image string) (repo, tag string) {
	i := strings.LastIndex(image, ":")
	if i < 0 || strings.Contains(image[i:], "/") {
		return image, ""
	}
	return image[:i], image[i+1:]
}

func checkCertManagerCompat(ctx context.Context, c *Cluster, up Upgrade) (*Result, error) {
	res, v, versioned, err := certManagerVersion(ctx, c)
	switch {
	case err == nil:
	case apierrors.IsForbidden(err):
		return Skip("no permission to list Deployments; cert-manager version unknown"), nil
	default:
		return nil, err
	}
	if res.Name == "" {
		return Skip("cert-manager not detected (no cert-manager-controller image in any Deployment)"), nil
	}
	if !versioned {
		return Warn("cert-manager found, but its image tag carries no version to check").
			WithResources(res).
			WithAction(ActionVerifyManually).
			WithRemediation("Confirm the cert-manager version by hand and compare it with %s.",
				deprecation.CertManagerSource).
			WithDocs(deprecation.CertManagerSource), nil
	}

	cm := v.MinorString()
	rel, known, older := deprecation.CertManagerRelease(cm)
	if !known && !older {
		return Skip("cert-manager %s is newer than kupre's copy of the support matrix", cm), nil
	}
	res.Detail = "cert-manager " + v.String()

	var problems []string
	switch {
	case older:
		problems = append(problems, fmt.Sprintf("cert-manager %s predates every release in the "+
			"vendor's support matrix and is long past end of life", cm))
	case rel.EOL != "":
		if t, err := time.Parse(time.DateOnly, rel.EOL); err == nil && !t.After(now()) {
			problems = append(problems, fmt.Sprintf("cert-manager %s reached end of life on %s "+
				"and gets no fixes", cm, rel.EOL))
		}
	}
	if !older {
		for _, k := range uniqueMinors(up.From.MinorString(), up.To.MinorString()) {
			if !rel.Supports(k) {
				problems = append(problems, fmt.Sprintf("cert-manager %s supports Kubernetes "+
					"%s to %s, not %s", cm, rel.MinKube, rel.MaxKube, k))
			}
		}
	}
	if len(problems) == 0 {
		return Pass("cert-manager %s is supported on Kubernetes %s", cm, up.To.MinorString()), nil
	}

	var fix string
	if want := deprecation.CertManagerReleaseSupporting(up.To.MinorString()); want != "" {
		fix = fmt.Sprintf("Upgrade cert-manager to %s or newer before upgrading Kubernetes, one "+
			"minor at a time per the cert-manager upgrade guide.", want)
	} else {
		fix = fmt.Sprintf("No released cert-manager version lists Kubernetes %s support yet. Hold "+
			"the upgrade until one does, or test cert-manager on %s yourself and accept the risk.",
			up.To.MinorString(), up.To.MinorString())
	}
	return Warn("%s", strings.Join(problems, "; ")).
		WithResources(res).
		WithRemediation("%s", fix).
		WithDocs(deprecation.CertManagerSource), nil
}

func uniqueMinors(a, b string) []string {
	if a == b {
		return []string{a}
	}
	return []string{a, b}
}
