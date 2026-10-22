package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/Rusty-Gopher/kupre/pkg/deprecation"
)

// AddonChecks compare installed cluster add-ons with the Kubernetes versions
// their vendors publish, one check per add-on in deprecation.Addons.
func AddonChecks() []Check {
	var out []Check
	for _, a := range deprecation.Addons {
		a := a
		out = append(out, Check{
			Name:        strings.ToLower(a.Name) + "-compatibility",
			Description: fmt.Sprintf("%s version against the Kubernetes versions its vendor publishes", a.Name),
			Category:    CategoryWorkload,
			Severity:    SeverityWarning,
			Action:      ActionPlanAhead,
			Evidence: fmt.Sprintf("Reads the %s version from the image tag of its Deployment or "+
				"DaemonSet and compares it with the matrix the vendor publishes (%s), embedded "+
				"in kupre.", a.Name, a.Source),
			Limits: fmt.Sprintf("Outside the published range means the vendor makes no promise, "+
				"not that %s is broken. A digest-only or re-tagged image cannot be versioned. "+
				"Vendor or distribution builds (LTS, managed dataplanes) may have their own "+
				"support terms.", a.Name),
			Run: func(ctx context.Context, c *Cluster, up Upgrade) (*Result, error) {
				return checkAddonCompat(ctx, c, up, a)
			},
		})
	}
	return out
}

// addonVersion finds the workload running the add-on's image and its version.
func addonVersion(ctx context.Context, c *Cluster, a deprecation.Addon) (AffectedResource, Version, bool, error) {
	deploys, err := c.Deployments(ctx)
	if err != nil {
		return AffectedResource{}, Version{}, false, err
	}
	dss, err := c.DaemonSets(ctx)
	if err != nil {
		return AffectedResource{}, Version{}, false, err
	}

	type workload struct {
		kind, ns, name string
		spec           corev1.PodSpec
	}
	var all []workload
	for _, d := range deploys {
		all = append(all, workload{"Deployment", d.Namespace, d.Name, d.Spec.Template.Spec})
	}
	for _, d := range dss {
		all = append(all, workload{"DaemonSet", d.Namespace, d.Name, d.Spec.Template.Spec})
	}

	for _, w := range all {
		for _, ctr := range w.spec.Containers {
			// A digest pins content but carries no version; drop it, then
			// read the version from the tag if there is one.
			ref, _, _ := strings.Cut(ctr.Image, "@")
			repo, tag := splitImageTag(ref)
			if repo != a.Image && !strings.HasSuffix(repo, "/"+a.Image) {
				continue
			}
			res := AffectedResource{Kind: w.kind, APIVersion: "apps/v1",
				Namespace: w.ns, Name: w.name, Detail: "image " + ctr.Image}
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

func checkAddonCompat(ctx context.Context, c *Cluster, up Upgrade, a deprecation.Addon) (*Result, error) {
	res, v, versioned, err := addonVersion(ctx, c, a)
	switch {
	case err == nil:
	case apierrors.IsForbidden(err):
		return Skip("no permission to list Deployments and DaemonSets; %s version unknown", a.Name), nil
	default:
		return nil, err
	}
	if res.Name == "" {
		return Skip("%s not detected (no %s image in any Deployment or DaemonSet)", a.Name, a.Image), nil
	}
	if !versioned {
		return Warn("%s found, but its image tag carries no version to check", a.Name).
			WithResources(res).
			WithAction(ActionVerifyManually).
			WithRemediation("Confirm the %s version by hand and compare it with %s.", a.Name, a.Source).
			WithDocs(a.Source), nil
	}

	minor := v.MinorString()
	rel, known, older := a.Release(minor)
	if !known && !older {
		return Skip("%s %s is newer than kupre's copy of the vendor matrix", a.Name, minor), nil
	}
	res.Detail = a.Name + " " + v.String()

	var problems []string
	switch {
	case older && a.OlderUnmaintained:
		problems = append(problems, fmt.Sprintf("%s %s predates every release in the vendor's "+
			"matrix and is no longer maintained", a.Name, minor))
	case older:
		problems = append(problems, fmt.Sprintf("%s %s predates every release in the vendor's "+
			"published matrix, so nothing vouches for it on this cluster", a.Name, minor))
	case rel.Unmaintained:
		problems = append(problems, fmt.Sprintf("%s %s is no longer a maintained release", a.Name, minor))
	case rel.EOL != "":
		if t, err := time.Parse(time.DateOnly, rel.EOL); err == nil && !t.After(now()) {
			problems = append(problems, fmt.Sprintf("%s %s reached end of life on %s and gets no fixes",
				a.Name, minor, rel.EOL))
		}
	}
	if !older {
		for _, k := range uniqueMinors(up.From.MinorString(), up.To.MinorString()) {
			if !rel.Covers(k) {
				problems = append(problems, fmt.Sprintf("%s %s %s Kubernetes %s to %s, not %s",
					a.Name, minor, a.Claim, rel.MinKube, rel.MaxKube, k))
			}
		}
	}
	if len(problems) == 0 {
		return Pass("%s %s %s Kubernetes %s", a.Name, minor, a.Claim, up.To.MinorString()), nil
	}

	var fix string
	if want := a.NewestCovering(up.To.MinorString()); want != "" {
		fix = fmt.Sprintf("Upgrade %s to %s or newer before upgrading Kubernetes, following the "+
			"vendor's upgrade path one minor at a time.", a.Name, want)
	} else {
		fix = fmt.Sprintf("No maintained %s release lists Kubernetes %s yet. Wait for one, or test "+
			"%s on %s yourself and accept the risk.", a.Name, up.To.MinorString(), a.Name,
			up.To.MinorString())
	}
	return Warn("%s", strings.Join(problems, "; ")).
		WithResources(res).
		WithRemediation("%s", fix).
		WithDocs(a.Source), nil
}

func uniqueMinors(a, b string) []string {
	if a == b {
		return []string{a}
	}
	return []string{a, b}
}
