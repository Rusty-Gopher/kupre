package analyzer

import (
	"context"
	"fmt"
	"slices"
	"strings"

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
			Name:        a.CheckName(),
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

// addonInstall is one workload running the add-on.
type addonInstall struct {
	res       AffectedResource
	version   Version
	versioned bool
}

// addonInstalls finds every workload running the add-on's image. Clusters can
// run more than one copy (a second namespace, a half-finished migration), and
// the oldest is the one that matters.
func addonInstalls(ctx context.Context, c *Cluster, a deprecation.Addon) ([]addonInstall, error) {
	deploys, err := c.Deployments(ctx)
	if err != nil {
		return nil, err
	}
	dss, err := c.DaemonSets(ctx)
	if err != nil {
		return nil, err
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

	var out []addonInstall
	for _, w := range all {
		for _, ctr := range w.spec.Containers {
			// A digest pins content but carries no version; drop it, then
			// read the version from the tag if there is one.
			ref, _, _ := strings.Cut(ctr.Image, "@")
			repo, tag := splitImageTag(ref)
			if repo != a.Image && !strings.HasSuffix(repo, "/"+a.Image) {
				continue
			}
			v, perr := ParseVersion(tag)
			out = append(out, addonInstall{
				res: AffectedResource{Kind: w.kind, APIVersion: "apps/v1",
					Namespace: w.ns, Name: w.name, Detail: "image " + ctr.Image},
				version: v, versioned: perr == nil,
			})
			break // one version per workload
		}
	}
	return out, nil
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
	installs, err := addonInstalls(ctx, c, a)
	switch {
	case err == nil:
	case apierrors.IsForbidden(err):
		return Skip("no permission to list Deployments and DaemonSets; %s version unknown", a.Name), nil
	default:
		return nil, err
	}
	if len(installs) == 0 {
		return Skip("%s not detected (no %s image in any Deployment or DaemonSet)", a.Name, a.Image), nil
	}

	var (
		problems, unknown, minors []string
		affected                  []AffectedResource
		seen                      = map[string]bool{}
		allUnversioned            = true
	)
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			problems = append(problems, p)
		}
	}
	for _, in := range installs {
		if !in.versioned {
			add(fmt.Sprintf("%s image tag carries no version to check", a.Name))
			affected = append(affected, in.res)
			continue
		}
		allUnversioned = false
		minor := in.version.MinorString()
		if !slices.Contains(minors, minor) {
			minors = append(minors, minor)
		}
		res := in.res
		res.Detail = a.Name + " " + in.version.String()
		rel, known, older := a.Release(minor)
		if !known && !older {
			unknown = append(unknown, fmt.Sprintf("%s %s is newer than kupre's copy of the vendor matrix", a.Name, minor))
			continue
		}
		before := len(problems)
		for _, p := range addonProblems(a, rel, minor, older, up) {
			add(p)
		}
		if len(problems) > before {
			affected = append(affected, res)
		}
	}

	if len(problems) == 0 {
		if len(unknown) > 0 {
			// Something was not checked, so this cannot be a pass.
			return Skip("%s", strings.Join(unknown, "; ")), nil
		}
		return Pass("%s %s %s Kubernetes %s", a.Name, strings.Join(minors, ", "), a.Claim,
			up.To.MinorString()), nil
	}
	problems = append(problems, unknown...)

	r := Warn("%s", strings.Join(problems, "; ")).WithResources(affected...).WithDocs(a.Source)
	if allUnversioned {
		return r.WithAction(ActionVerifyManually).
			WithRemediation("Confirm the %s version by hand and compare it with %s.", a.Name, a.Source), nil
	}
	if want := a.NewestCovering(up.To.MinorString(), now()); want != "" {
		return r.WithRemediation("Upgrade %s to %s or newer before upgrading Kubernetes, following "+
			"the vendor's upgrade path one minor at a time.", a.Name, want), nil
	}
	return r.WithRemediation("No maintained %s release lists Kubernetes %s yet. Wait for one, or "+
		"test %s on %s yourself and accept the risk.", a.Name, up.To.MinorString(), a.Name,
		up.To.MinorString()), nil
}

// addonProblems lists what is wrong with one installed release.
func addonProblems(a deprecation.Addon, rel deprecation.AddonRelease, minor string, older bool, up Upgrade) []string {
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
	case !rel.Maintained(now()):
		problems = append(problems, fmt.Sprintf("%s %s reached end of life on %s and gets no fixes",
			a.Name, minor, rel.EOL))
	}
	if !older {
		for _, k := range uniqueMinors(up.From.MinorString(), up.To.MinorString()) {
			if !rel.Covers(k) {
				problems = append(problems, fmt.Sprintf("%s %s %s Kubernetes %s to %s, not %s",
					a.Name, minor, a.Claim, rel.MinKube, rel.MaxKube, k))
			}
		}
	}
	return problems
}

func uniqueMinors(a, b string) []string {
	if a == b {
		return []string{a}
	}
	return []string{a, b}
}
